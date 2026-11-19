#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Générateur de rapport final — Lab Metasploitable (tâche T11).

Convertit une source Markdown en PDF via une étape HTML intermédiaire rendue
par weasyprint. Le Markdown reste la source de vérité ; le PDF en est le rendu.

Conformes aux standards dev :
- Python 3.11+, argparse, codes de sortie explicites.
- Options --source, --output, --dry-run, --timeout, --verbose.
- Aucune IP, aucun identifiant, aucun secret codé en dur.
- Journalisation horodatée.
- Idempotent : regénérer écrase le PDF de sortie sans toucher aux preuves brutes.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

try:
    from weasyprint import HTML  # type: ignore
except ImportError as exc:  # pragma: no cover - dépendance d'environnement
    print(f"ERREUR : weasyprint n'est pas disponible : {exc}", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

DEFAULT_CSS: Final[str] = """
@page {
    size: A4;
    margin: 2cm 2cm 2.2cm 2cm;
    @bottom-center {
        content: "Lab Metasploitable — rapport final — page " counter(page) " sur " counter(pages);
        font-size: 8pt;
        color: #666;
    }
    @top-right {
        content: "Classification : lab local — usage interne";
        font-size: 8pt;
        color: #999;
    }
}
body { font-family: "DejaVu Sans", sans-serif; font-size: 9.5pt; line-height: 1.5; color: #222; }
h1 { font-size: 20pt; color: #1a3a5c; border-bottom: 2px solid #1a3a5c; padding-bottom: 4px; page-break-after: avoid; }
h2 { font-size: 15pt; color: #1a3a5c; border-bottom: 1px solid #9db2c8; page-break-after: avoid; }
h3 { font-size: 12pt; color: #2c5f8a; page-break-after: avoid; }
p { margin: 0 0 8px 0; text-align: justify; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 14px 0; font-size: 8.5pt; }
th { background: #1a3a5c; color: #fff; padding: 5px 7px; text-align: left; border: 1px solid #1a3a5c; }
td { padding: 4px 7px; border: 1px solid #b9c6d4; vertical-align: top; }
tr:nth-child(even) td { background: #f2f5f9; }
code { font-family: "DejaVu Sans Mono", monospace; font-size: 8.5pt; background: #eef2f6; padding: 1px 4px; border-radius: 3px; }
pre { background: #eef2f6; border: 1px solid #b9c6d4; border-radius: 4px; padding: 8px; overflow-x: auto; font-size: 8.5pt; page-break-inside: avoid; }
blockquote { border-left: 3px solid #1a3a5c; margin: 8px 0 8px 16px; padding: 4px 12px; color: #444; background: #f7f9fb; }
ul, ol { margin: 4px 0 10px 0; padding-left: 20px; }
li { margin-bottom: 3px; text-align: justify; }
hr { border: none; border-top: 1px solid #9db2c8; margin: 14px 0; }
.cover { text-align: center; padding-top: 80px; }
.cover h1 { font-size: 26pt; border: none; }
.cover .meta { margin-top: 40px; font-size: 11pt; color: #444; }
.toc-title { font-size: 15pt; color: #1a3a5c; border-bottom: 1px solid #9db2c8; }
"""

# ---------------------------------------------------------------------------
# Journalisation
# ---------------------------------------------------------------------------

def log(message: str, verbose: bool = False, level: str = "INFO") -> None:
    """Écrit un message journalisé horodaté (UTC) sur stdout."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    prefix = f"[{ts}] [{level}]"
    if level == "INFO" and not verbose:
        # On affiche les INFO importantes quand même (génération, erreurs).
        pass
    print(f"{prefix} {message}", file=sys.stdout)


# ---------------------------------------------------------------------------
# Convertisseur Markdown -> HTML (dédié, sans dépendance externe)
# ---------------------------------------------------------------------------

def _escape(text: str) -> str:
    return html.escape(text, quote=False)


def _inline(md: str) -> str:
    """Convertit les éléments en ligne d'un paragraphe Markdown en HTML."""
    # Code inline `...` (avant les autres pour protéger le contenu)
    md = re.sub(r"`([^`]+)`", r"<code>\1</code>", md)
    # Liens [texte](url)
    md = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', md)
    # Gras **...** (non gourmand)
    md = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", md)
    # Italique *...*
    md = re.sub(r"\*(.+?)\*", r"<em>\1</em>", md)
    return _escape_preserve_tags(md)


_TAG_RE = re.compile(r"(<[^>]+>)")


def _escape_preserve_tags(text: str) -> str:
    """Échappe le texte tout en préservant les balises HTML déjà produites."""
    parts = _TAG_RE.split(text)
    out = []
    for part in parts:
        if _TAG_RE.fullmatch(part):
            out.append(part)
        else:
            out.append(_escape(part))
    return "".join(out)


def _convert_code_block(content: str, lang: str) -> str:
    escaped = html.escape(content, quote=False)
    class_attr = f' class="lang-{lang}"' if lang else ""
    return f"<pre><code{class_attr}>{escaped}</code></pre>"


def markdown_to_html(md_text: str) -> str:
    """Convertit un document Markdown complet en fragment HTML <body>."""
    lines = md_text.split("\n")
    html_parts: list[str] = []
    i = 0
    n = len(lines)
    in_list = False
    in_blockquote = False
    in_table = False
    table_rows: list[str] = []

    def flush_list() -> None:
        nonlocal in_list
        if in_list:
            html_parts.append("</ul>")
            in_list = False

    def flush_blockquote() -> None:
        nonlocal in_blockquote
        if in_blockquote:
            html_parts.append("</blockquote>")
            in_blockquote = False

    def flush_table() -> None:
        nonlocal in_table, table_rows
        if in_table and table_rows:
            header = table_rows[0]
            body = "".join(table_rows[1:])
            html_parts.append("<table><thead>" + header + "</thead><tbody>" + body + "</tbody></table>")
        in_table = False
        table_rows = []

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # --- Bloc de code fencé ``` ---
        if stripped.startswith("```"):
            flush_list()
            flush_blockquote()
            flush_table()
            lang = stripped[3:].strip()
            content_lines: list[str] = []
            i += 1
            while i < n and not lines[i].strip().startswith("```"):
                content_lines.append(lines[i])
                i += 1
            # Sauter le marqueur de fermeture s'il existe
            if i < n:
                i += 1
            html_parts.append(_convert_code_block("\n".join(content_lines), lang))
            continue

        # --- Ligne vide : fermeture des blocs ouverts ---
        if stripped == "":
            flush_list()
            flush_blockquote()
            flush_table()
            html_parts.append("")
            i += 1
            continue

        # --- Règle horizontale ---
        if re.fullmatch(r"-{3,}|\*{3,}|_{3,}", stripped):
            flush_list()
            flush_blockquote()
            flush_table()
            html_parts.append("<hr>")
            i += 1
            continue

        # --- En-têtes ---
        m = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if m:
            flush_list()
            flush_blockquote()
            flush_table()
            level = len(m.group(1))
            text = m.group(2).strip()
            html_parts.append(f"<h{level}>{_inline(text)}</h{level}>")
            i += 1
            continue

        # --- Tableau (ligne commençant par |) ---
        if stripped.startswith("|") and stripped.endswith("|"):
            flush_list()
            flush_blockquote()
            in_table = True
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            # Ligne de séparation |---|---| : on l'ignore (déjà gérée par l'en-tête)
            if all(re.fullmatch(r":?-{3,}:?", c) for c in cells if c):
                i += 1
                continue
            row_html = ""
            for c in cells:
                row_html += f"<td>{_inline(c)}</td>"
            table_rows.append("<tr>" + row_html + "</tr>")
            i += 1
            continue

        # Si on est dans un tableau et que la ligne ne commence pas par |, on ferme le tableau
        if in_table:
            flush_table()

        # --- Citation > ---
        if stripped.startswith(">"):
            flush_list()
            flush_table()
            if not in_blockquote:
                html_parts.append("<blockquote>")
                in_blockquote = True
            content = stripped[1:].strip()
            html_parts.append(f"<p>{_inline(content)}</p>")
            i += 1
            continue

        # --- Liste à puces - ---
        m = re.match(r"^-\s+(.+)$", stripped)
        if m:
            flush_blockquote()
            flush_table()
            if not in_list:
                html_parts.append("<ul>")
                in_list = True
            html_parts.append(f"<li>{_inline(m.group(1))}</li>")
            i += 1
            continue

        # --- Paragraphe normal ---
        flush_list()
        flush_blockquote()
        flush_table()
        # Rassembler les lignes consécutives non vides et non spéciales en un paragraphe
        para_lines: list[str] = [stripped]
        i += 1
        while i < n:
            nxt = lines[i]
            nxt_stripped = nxt.strip()
            if nxt_stripped == "":
                break
            if (re.match(r"^(#{1,6})\s+", nxt_stripped)
                    or nxt_stripped.startswith("```")
                    or re.fullmatch(r"-{3,}|\*{3,}|_{3,}", nxt_stripped)
                    or nxt_stripped.startswith("|")
                    or nxt_stripped.startswith(">")
                    or re.match(r"^-\s+", nxt_stripped)):
                break
            para_lines.append(nxt_stripped)
            i += 1
        html_parts.append("<p>" + _inline(" ".join(para_lines)) + "</p>")

    # Fermetures finales
    flush_list()
    flush_blockquote()
    flush_table()

    return "\n".join(html_parts)


def build_html_document(md_text: str, title: str) -> str:
    """Enveloppe le fragment HTML dans un document complet avec CSS."""
    body = markdown_to_html(md_text)
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>{DEFAULT_CSS}</style>
</head>
<body>
{body}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Génération PDF
# ---------------------------------------------------------------------------

def generate_pdf(source: Path, output: Path, dry_run: bool = False, verbose: bool = False,
                 timeout: int = 120) -> int:
    """Génère le PDF à partir de la source Markdown. Retourne 0 en cas de succès."""
    if not source.is_file():
        log(f"Fichier source introuvable : {source}", verbose=False, level="ERREUR")
        return 1

    md_text = source.read_text(encoding="utf-8")
    if not md_text.strip():
        log(f"Fichier source vide : {source}", verbose=False, level="ERREUR")
        return 1

    # Titre : première ligne commençant par #, sinon le nom du fichier
    title = "Rapport final"
    for line in md_text.splitlines():
        if line.strip().startswith("# "):
            title = line.strip()[2:].strip()
            break

    log(f"Source lue : {source} ({len(md_text)} caractères, {len(md_text.splitlines())} lignes)", verbose)
    log(f"Titre détecté : {title}", verbose)

    html_doc = build_html_document(md_text, title)

    if dry_run:
        log("[DRY-RUN] Conversion Markdown -> HTML -> PDF simulée (aucun fichier écrit).", verbose)
        log(f"[DRY-RUN] HTML intermédiaire : {len(html_doc)} caractères.", verbose)
        log(f"[DRY-RUN] PDF cible : {output}", verbose)
        return 0

    # Écriture HTML intermédiaire temporaire (à côté du output, supprimée après)
    html_tmp = output.with_suffix(".html")
    html_tmp.write_text(html_doc, encoding="utf-8")
    log(f"HTML intermédiaire écrit : {html_tmp} ({len(html_doc)} caractères)", verbose)

    try:
        log(f"Rendu weasyprint -> {output} (timeout {timeout}s)", verbose)
        start = time.time()
        HTML(string=html_doc, base_url=str(source.parent)).write_pdf(str(output))
        elapsed = time.time() - start
        log(f"PDF généré en {elapsed:.2f}s : {output}", verbose)
    except Exception as exc:  # noqa: BLE001 - rapport d'erreur explicite
        log(f"Échec de la génération PDF par weasyprint : {exc}", verbose=False, level="ERREUR")
        return 1
    finally:
        # Nettoyage du fichier HTML intermédiaire (artefact de travail, pas une preuve)
        if html_tmp.exists():
            html_tmp.unlink()
            log(f"Fichier intermédiaire supprimé : {html_tmp}", verbose)

    # Vérification post-génération
    if not output.is_file() or output.stat().st_size == 0:
        log(f"Le PDF généré est absent ou vide : {output}", verbose=False, level="ERREUR")
        return 1

    log(f"PDF vérifié : {output.stat().st_size} octets", verbose)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Génère le rapport final PDF depuis une source Markdown (weasyprint).",
    )
    parser.add_argument("--source", required=True, type=Path,
                        help="Chemin du fichier Markdown source (ex: reports/rapport-final.md)")
    parser.add_argument("--output", required=True, type=Path,
                        help="Chemin du fichier PDF de sortie (ex: reports/rapport-final.pdf)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simule la génération sans écrire le PDF")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Timeout maximal pour le rendu weasyprint (secondes, défaut 120)")
    parser.add_argument("--verbose", action="store_true",
                        help="Affichage détaillé des étapes")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    start_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    log(f"Démarrage generate_report.py (source={args.source}, output={args.output})", args.verbose)

    rc = generate_pdf(
        source=args.source,
        output=args.output,
        dry_run=args.dry_run,
        verbose=args.verbose,
        timeout=args.timeout,
    )

    end_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if rc == 0:
        log(f"Terminé avec succès ({start_ts} -> {end_ts})", args.verbose)
    else:
        log(f"Terminé en erreur (code {rc})", verbose=False, level="ERREUR")
    return rc


if __name__ == "__main__":
    sys.exit(main())
