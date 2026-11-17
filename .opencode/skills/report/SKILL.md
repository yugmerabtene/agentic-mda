---
name: report
description: "Rédaction et génération du rapport de mission : structure, traçabilité des preuves, PDF reproductible avec pandoc ou weasyprint. À charger pour produire reports/rapport-final.md et reports/rapport-final.pdf."
---

# Documentation et rapport final

## Principes

- Le rapport est en français, factuel, reproductible et traçable.
- Chaque affirmation technique renvoie à une preuve ou à une source : `evidence/raw/`,
  `data/services.json`, `data/cves.json`, `plans/attack-plan.json`.
- Aucune CVE, aucun identifiant MITRE et aucun résultat ne doit être inventé.
- Le rapport ne contient aucun secret, identifiant ou token.
- Le Markdown est la source de vérité ; le PDF est généré depuis celui-ci.

## Structure recommandée

1. Page de couverture : titre, auteur, date, version, classification « lab local ».
2. Résumé exécutif : objectif, cible, résultats clés, risques majeurs.
3. Périmètre et autorisation : IP cible, réseau, limites, date de confirmation.
4. Environnement et méthodologie : outils, versions, options de scan, limites.
5. Inventaire des services : tableau service/port/version/preuve.
6. Analyse CVE : tableau CVE, service, CVSS, confiance, source, statut KEV/EPSS.
7. Plan d'attaque MITRE : synthèse par tactique, étapes, préconditions, risques.
8. Preuves : inventaire des fichiers, horodatages, empreintes SHA-256.
9. Remédiation : recommandations priorisées par risque.
10. Limites et risques résiduels.
11. Annexes : commandes, journaux, références.

## Génération

Vérifier les outils disponibles :

```bash
command -v pandoc
command -v weasyprint
command -v pdftotext
```

Chaîne de référence :

```bash
pandoc reports/rapport-final.md \
  --from markdown --to pdf \
  --pdf-engine=xelatex \
  --toc --number-sections \
  -o reports/rapport-final.pdf
```

Alternative sans LaTeX :

```bash
pandoc reports/rapport-final.md -f markdown -t html5 -s --toc \
  -o reports/rapport-final.html
weasyprint reports/rapport-final.html reports/rapport-final.pdf
```

Si un moteur manque, installer la dépendance dans `.venv` ou documenter la commande
utilisée. Ne pas livrer un PDF vide ou partiel.

## Contrôles avant livraison

- [ ] Le Markdown source est complet et relu.
- [ ] Le PDF existe, s'ouvre et contient toutes les sections.
- [ ] `pdftotext reports/rapport-final.pdf -` restitue le titre et la conclusion.
- [ ] `pdfinfo` indique un nombre de pages cohérent.
- [ ] Les tableaux CVE et MITRE sont cohérents avec les fichiers JSON.
- [ ] Les chemins de preuves cités existent.
- [ ] Aucune donnée sensible ou hors périmètre.
- [ ] La commande de génération est documentée dans le rapport ou le dépôt.
- [ ] Le rapport mentionne les limites et les risques résiduels.

## Traçabilité

- Référencer les fichiers de preuve par chemin relatif.
- Conserver les horodatages UTC.
- Signaler les services non corrélés et les CVE à confiance faible.
- Distinguer clairement les faits observés des hypothèses.
