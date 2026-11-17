---
name: common
description: "Règles partagées du lab cybersécurité (périmètre, workflow, conventions, tracking.json, definition of done). À charger avant toute tâche par l'orchestrateur, le dev et le reviewer."
---

# Règles communes du projet

## Périmètre

- Mission limitée à une VM Metasploitable locale sur hyperviseur, en réseau privé
  RFC1918 (10/8, 172.16/12, 192.168/16) ou loopback.
- L'IP cible doit être confirmée par l'utilisateur et présente dans `tracking.json` avant
  le premier scan.
- Toute cible publique, tout domaine tiers ou actif hors lab est refusé.
- Actions intrusives ou destructrices (exploit, brute force, modification de service,
  persistance, exfiltration) : confirmation utilisateur explicite obligatoire.
- Ne jamais écrire d'identifiant, token ou secret dans un livrable ou une preuve.

## Langue et conventions

- Prompts, documentation, rapports et commentaires : français.
- Identifiants de code, noms de variables, fonctions et fichiers : anglais ou
  `kebab-case` pour les fichiers.
- JSON valide UTF-8, indentation 2 espaces, aucun commentaire.
- Horodatages ISO 8601 UTC : `YYYY-MM-DDTHH:MM:SSZ`.
- Identifiants de tâche : `T01`, `T02`, ... ; identifiants de revue : `R-001`, ...
- Preuves brutes immuables dans `evidence/raw/` ; toute transformation va dans
  `evidence/normalized/` ou `data/`.

## Arborescence

```
scripts/recon/          scripts/cve/          scripts/report/
tests/unit/             tests/integration/    tests/e2e/
configs/                data/                 evidence/raw/
evidence/normalized/    plans/                reports/
review/
```

## Workflow et gates

1. Cadrage : cible, périmètre, livrables, critères d'acceptation.
2. Environnement : dépendances, outils, arborescence.
3. Reconnaissance : script + exécution + preuves.
4. Corrélation CVE : service/version → CVE avec source et confiance.
5. Plan MITRE : JSON + Markdown cohérents.
6. Documentation : Markdown source + PDF.
7. Revue finale : livrables, reproductibilité, preuves.
8. Clôture : synthèse, risques résiduels, suites.

Chaque phase est suivie d'une revue indépendante. Un `PASS` est obligatoire pour clore
une tâche. En cas de `CHANGES_REQUIRED`, le dev corrige et le reviewer re-contrôle.

## Contrat tracking.json

Statuts autorisés : `pending`, `in_progress`, `review`, `changes_required`, `done`,
`blocked`, `cancelled`.

Phases autorisées : `cadrage`, `environnement`, `recon`, `cve`, `mitre`,
`documentation`, `revue_finale`, `cloture`.

Structure minimale :

```json
{
  "schema_version": "1.0",
  "mission": {
    "name": "...",
    "scope": "...",
    "target": { "name": "...", "ip": null, "hostname": null, "network": null },
    "deliverables": [],
    "created_at": "YYYY-MM-DDTHH:MM:SSZ",
    "updated_at": "YYYY-MM-DDTHH:MM:SSZ"
  },
  "workflow": { "current_phase": "cadrage", "status": "pending", "next_task": "T01" },
  "tasks": [
    {
      "id": "T01",
      "phase": "cadrage",
      "title": "...",
      "owner": "orchestrator | dev | reviewer",
      "status": "pending",
      "depends_on": [],
      "acceptance": [],
      "artifacts": [],
      "review": null
    }
  ],
  "reviews": [],
  "decisions": [],
  "blockers": []
}
```

Toute transition de statut met à jour `updated_at`. Un blocage est consigné dans
`blockers` avec la décision attendue de l'utilisateur.

## Paquet de tâche (orchestrateur → dev)

- ID et titre de la tâche, phase, objectif.
- Entrées disponibles et chemins.
- Contraintes de périmètre et de sécurité.
- Critères d'acceptation vérifiables.
- Artefacts attendus et format.
- Commandes de test attendues.

## Paquet de revue (dev → reviewer)

- Fichiers créés ou modifiés.
- Tests exécutés avec commandes et résultats.
- Artefacts et preuves avec horodatage.
- Critères d'acceptation et preuves associées.
- Limites, risques et points d'attention.

## Definition of done

- Critères d'acceptation satisfaits.
- Tests requis passants et commandes documentées.
- Artefacts présents aux chemins prévus.
- Verdict reviewer `PASS`.
- `tracking.json` à jour.
- Risques résiduels et limites consignés.

## Anti-patterns interdits

- Inventer un CVE, une technique MITRE, une preuve ou un résultat de test.
- Modifier `evidence/raw/` ou écrire dans `review/` hors reviewer.
- Marquer `done` sans revue indépendante.
- Scanner une cible non confirmée ou publique.
- Mettre un secret dans un fichier de mission.
