#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests unitaires de scripts/report/generate_report.py.

Ces tests ne touchent pas le réseau ni la cible lab. Ils valident le
convertisseur Markdown -> HTML, la structure du document HTML et le comportement
CLI (y compris --dry-run et le rejet d'une source absente).
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

# Chargement du module sous test (scripts/report/generate_report.py)
MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "report" / "generate_report.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("generate_report", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gr = _load_module()


# ---------------------------------------------------------------------------
# Convertisseur Markdown -> HTML
# ---------------------------------------------------------------------------

def test_markdown_headings():
    md = "# Titre principal\n## Sous-titre\n### Sous-sous-titre"
    html = gr.markdown_to_html(md)
    assert "<h1>Titre principal</h1>" in html
    assert "<h2>Sous-titre</h2>" in html
    assert "<h3>Sous-sous-titre</h3>" in html


def test_markdown_bold_italic_code_link():
    md = "du **gras** et de l'*italique* avec du `code` et un [lien](https://example.com)."
    html = gr.markdown_to_html(md)
    assert "<strong>gras</strong>" in html
    assert "<em>italique</em>" in html
    assert "<code>code</code>" in html
    assert '<a href="https://example.com">lien</a>' in html


def test_markdown_table():
    md = "| Port | Service | Version |\n|------|---------|---------|\n| 21/tcp | ftp | 2.3.4 |"
    html = gr.markdown_to_html(md)
    assert "<table>" in html
    assert "<thead>" in html
    assert "<tbody>" in html
    assert "<td>21/tcp</td>" in html
    assert "<td>ftp</td>" in html
    assert "<td>2.3.4</td>" in html


def test_markdown_list():
    md = "- premier élément\n- deuxième élément"
    html = gr.markdown_to_html(md)
    assert "<ul>" in html
    assert "<li>premier élément</li>" in html
    assert "<li>deuxième élément</li>" in html
    assert "</ul>" in html


def test_markdown_code_block():
    md = "```bash\nnmap -sV 192.168.56.103\n```"
    html = gr.markdown_to_html(md)
    assert "<pre>" in html
    assert "<code" in html
    assert "nmap -sV 192.168.56.103" in html


def test_markdown_horizontal_rule():
    md = "texte avant\n---\ntexte après"
    html = gr.markdown_to_html(md)
    assert "<hr>" in html


def test_markdown_blockquote():
    md = "> ceci est une citation"
    html = gr.markdown_to_html(md)
    assert "<blockquote>" in html
    assert "ceci est une citation" in html


def test_markdown_empty():
    assert gr.markdown_to_html("") == ""
    assert gr.markdown_to_html("\n\n").strip() == ""


def test_build_html_document_wraps_body():
    html = gr.build_html_document("# Mon rapport\n\nUn paragraphe.", "Mon rapport")
    assert "<!DOCTYPE html>" in html
    assert '<html lang="fr">' in html
    assert '<title>Mon rapport</title>' in html
    assert "<h1>Mon rapport</h1>" in html
    assert "<p>Un paragraphe.</p>" in html
    assert "weasyprint" not in html  # CSS interne, pas de référence externe


# ---------------------------------------------------------------------------
# CLI / comportement de génération
# ---------------------------------------------------------------------------

def test_cli_requires_source_and_output(tmp_path, capsys):
    source = tmp_path / "rapport.md"
    source.write_text("# Test\n\nContenu.", encoding="utf-8")
    output = tmp_path / "rapport.pdf"

    rc = gr.main(["--source", str(source), "--output", str(output), "--verbose"])
    assert rc == 0
    assert output.is_file()
    assert output.stat().st_size > 0
    # Le fichier HTML intermédiaire ne doit pas persister
    assert not (tmp_path / "rapport.html").exists()


def test_cli_dry_run_does_not_write_pdf(tmp_path, capsys):
    source = tmp_path / "rapport.md"
    source.write_text("# Test\n\nContenu.", encoding="utf-8")
    output = tmp_path / "rapport.pdf"

    rc = gr.main(["--source", str(source), "--output", str(output), "--dry-run"])
    assert rc == 0
    assert not output.exists()


def test_cli_missing_source(tmp_path, capsys):
    output = tmp_path / "rapport.pdf"
    rc = gr.main(["--source", str(tmp_path / "inexistant.md"), "--output", str(output)])
    assert rc == 1
    assert not output.exists()


def test_cli_empty_source(tmp_path, capsys):
    source = tmp_path / "vide.md"
    source.write_text("", encoding="utf-8")
    output = tmp_path / "rapport.pdf"
    rc = gr.main(["--source", str(source), "--output", str(output)])
    assert rc == 1


def test_no_hardcoded_ip_in_module():
    """Le module ne doit pas embarquer d'adresse IP codée en dur."""
    source = MODULE_PATH.read_text(encoding="utf-8")
    # Recherche d'adresses IPv4 littérales dans le code source
    ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", source)
    assert ips == [], f"Adresses IP codées en dur détectées : {ips}"
