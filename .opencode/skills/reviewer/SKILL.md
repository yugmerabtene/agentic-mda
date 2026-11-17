---
name: reviewer
description: "Grille de revue indépendante : critères, tests d'acceptation, sécurité, validité des CVE et du mapping MITRE, verdict PASS/CHANGES_REQUIRED/BLOCKED. À charger par l'agent reviewer avant toute revue."
---

# Grille de revue

## Indépendance

- Ne pas modifier le code de production ni les données de mission.
- Écrire uniquement dans `review/` : rapport, tests d'acceptation, notes.
- Ne pas se fier aux affirmations du dev : relire les fichiers, relancer les tests,
  vérifier les sorties.
- Un conflit d'intérêt (reviewer ayant participé à l'implémentation) doit être signalé.

## Vérifications par catégorie

### 1. Conformité

- Chaque critère d'acceptation de la tâche est couvert et prouvé.
- Les artefacts attendus existent aux chemins convenus.
- Le périmètre est respecté (cible confirmée, RFC1918, pas d'action non autorisée).

### 2. Code

- Lisibilité, structure, nommage, docstrings.
- Gestion des erreurs et des cas limites : cible absente, outil manquant, timeout, sortie
  vide, XML/JSON invalide.
- Sécurité : injection de commandes, `shell=True`, traversée de chemins, secrets,
  permissions, désérialisation non sûre.
- Pas de dépendance inutile ni de code mort.
- Reproductibilité : versions, configuration, commandes.

### 3. Tests

- Existence et pertinence des tests unitaires, d'intégration et de bout en bout.
- Les tests unitaires n'utilisent pas le réseau réel.
- Exécution réelle :

```bash
pytest -m "not integration and not e2e"
pytest -m integration
pytest -m e2e        # uniquement si le lab est disponible
```

- Vérifier qu'un test échoue bien quand le code est cassé (revue par mutation légère si
  pertinent) et qu'aucun test n'est vide ou trivialement vrai.

### 4. Preuves et données

- Preuves brutes horodatées et non modifiées.
- Manifeste SHA-256 cohérent.
- Données normalisées traçables vers une preuve (`source`).
- Aucune donnée inventée, aucune valeur sans source.

### 5. CVE

- Format `CVE-YYYY-NNNN` valide.
- Chaque CVE existe dans une source autoritative (NVD, éditeur).
- Le rattachement service/version est justifié (CPE, plage de versions).
- Le niveau de confiance est cohérent avec la preuve.
- CVSS/KEV/EPSS, s'ils sont cités, proviennent d'une source et d'une date identifiables.
- Les faux positifs et services non corrélés sont signalés.

### 6. MITRE ATT&CK

- Tactiques et techniques existantes, identifiants exacts (`TAxxxx`, `Txxxx`,
  `Txxxx.xxx`).
- Chaque étape est rattachée à une technique pertinente, pas décorative.
- Les CVE citées existent dans `data/cves.json`.
- Le plan JSON et le Markdown sont cohérents.
- Les préconditions, preuves attendues, risques et conditions d'arrêt sont présents.
- Aucune étape destructive sans confirmation utilisateur.

### 7. Rapport PDF

- Génération rejouée avec la commande documentée.
- PDF lisible, pages complètes, table des matières et annexes cohérentes.
- Contenu aligné sur les sources ; pas de CVE ou de technique non vérifiée.
- `pdftotext` permet d'extraire le contenu attendu.

## Sévérités

- `blocker` : empêche l'acceptation ou viole le périmètre/sécurité.
- `critical` : donnée fausse (CVE/MITRE), preuve manquante, test mensonger.
- `major` : défaut fonctionnel, robustesse insuffisante, documentation incomplète.
- `minor` : qualité, maintenabilité, ambiguïté.
- `nit` : style sans impact.

## Règles de verdict

- `PASS` : tous les critères satisfaits, tests exécutés et passants, aucun blocker ni
  critical.
- `CHANGES_REQUIRED` : corrections nécessaires et réalisables par le dev.
- `BLOCKED` : accès, information ou décision utilisateur manquants ; ne pas deviner.

## Rapport

Créer `review/review-Txx-<timestamp>.md` avec : tâche, verdict, findings tabulaires,
commandes de test exactes et résultats, tableau des critères d'acceptation, risques
résiduels. Retourner le chemin et un résumé concis à l'orchestrateur.
