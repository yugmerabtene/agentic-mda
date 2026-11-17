---
name: dev
description: "Standards de développement du lab : scripts Python/Bash paramétrables, tests pytest, sécurité, preuves et télémétrie CVE. À charger par l'agent dev avant d'écrire ou modifier du code ou des artefacts techniques."
---

# Standards de développement

## Structure des scripts

- Python 3.11+, bibliothèque standard d'abord ; dépendances justifiées dans
  `requirements.txt`.
- CLI avec `argparse`, sous-commandes si utile, codes de sortie explicites.
- Options récurrentes : `--target`, `--output`, `--dry-run`, `--timeout`, `--verbose`.
- Aucune IP ni aucun identifiant codé en dur : configuration dans `configs/` ou args.
- Journalisation horodatée dans `evidence/raw/logs/` ou dans le répertoire de sortie.
- Idempotence : relancer une commande ne corrompt pas les preuves existantes ; nommer avec
  un horodatage UTC.

## Sécurité du code

- Pas de `shell=True`, pas `eval`, pas de concaténation de commandes non échappée.
- Valider strictement les entrées : IP, port, chemins, options.
- Refuser toute cible hors RFC1918 ou loopback, sauf mécanisme explicite de test avec
  confirmation utilisateur.
- Timeouts sur tous les appels réseau ; limites de taille et de durée pour les sorties.
- Ne jamais enregistrer de secret dans les logs ; masquer les valeurs sensibles.
- Écrire les fichiers de preuve en lecture seule après création si pertinent.

## Tests

- `pytest` avec `tests/unit/`, `tests/integration/`, `tests/e2e/`.
- Les tests unitaires ne touchent pas le réseau : mocker `subprocess`, `requests`, `socket`.
- Marqueurs :
  - `@pytest.mark.integration` pour les tests locaux nécessitant des outils ;
  - `@pytest.mark.e2e` pour les tests contre la VM du lab.
- Cas minimaux : arguments invalides, cible publique refusée, timeout, sortie vide,
  parsing XML nmap, JSON invalide, doublons CVE.
- Exécuter `pytest -m "not integration and not e2e"` avant le paquet de revue, puis les
  tests d'intégration disponibles.
- Documenter les commandes exactes et les résultats.

## Preuves et données

- Conserver les sorties brutes : `evidence/raw/<tool>-<target>-<timestamp>.xml|txt|json`.
- Normaliser dans `data/` avec un champ `source` pointant vers la preuve brute.
- Calculer un manifeste SHA-256 des preuves (`evidence/raw/manifest.sha256`).
- Ne jamais réécrire une preuve brute ; toute correction produit un nouveau fichier.
- Schémas JSON avec `schema_version`, `generated_at`, `target`.

## Corrélation CVE

- Extraire produit/version/CPE depuis nmap (`-sV`, XML) avant toute recherche.
- Sources : `searchsploit --json` local, API NVD 2.0, CISA KEV / EPSS si disponibles.
- Respecter les limites de l'API NVD (environ 5 requêtes/30 s sans clé) et mettre en
  cache les réponses.
- Ne jamais inventer ou compléter un CVE « de mémoire » : chaque identifiant doit venir
  d'une source enregistrée.
- Niveaux de confiance :
  - `high` : CPE/version exacte et source autoritative ;
  - `medium` : produit + plage de versions ou bannière précise ;
  - `low` : correspondance approximative à confirmer.
- Signaler les services sans CVE correspondante dans `unmatched_services`.

## Mapping MITRE et rapports

- Déléguer les règles de contenu aux skills `mitre` et `report`.
- Le plan JSON est la source de vérité ; le Markdown en est dérivé ou contrôlé pour
  cohérence.
- Ne citer que des techniques ATT&CK existantes et des CVE présentes dans `data/cves.json`.

## Avant de rendre le paquet

- [ ] Code exécuté au moins une fois en `--dry-run` et en réel si les conditions le
      permettent.
- [ ] Tests unitaires au vert.
- [ ] Fichiers formatés (ruff si disponible).
- [ ] Aucun secret, aucune IP publique, aucun artefact hors périmètre.
- [ ] Paquet de revue complet selon `common`.
