# AGENTS.md — Système agentique de lab cybersécurité

## Objet du dépôt

Ce dépôt pilote une mission de laboratoire local : reconnaissance automatisée d'une VM
Metasploitable, corrélation des services découverts avec des CVE, production d'un plan
d'attaque MITRE ATT&CK (Markdown + JSON) et documentation PDF reproductible.

Le contexte de mission détaillé se trouve dans `CONTEXT.md`. L'état d'avancement est
tenu dans `tracking.json`.

## Périmètre et règles de sécurité

- Cible uniquement locale : VM Metasploitable sur hyperviseur local, adresse IPv4 privée
  (RFC1918) ou loopback. Toute autre cible est hors périmètre.
- L'adresse cible doit être confirmée par l'utilisateur et renseignée dans
  `tracking.json` avant le premier scan.
- Ne jamais viser une IP publique, un domaine tiers ou un actif hors du lab.
- Les actions intrusives ou destructrices (exploit, brute force, modification de service,
  persistance, exfiltration) nécessitent une confirmation explicite de l'utilisateur,
  même en lab. En cas de doute : demander.
- Les identifiants, tokens et secrets restent dans `.env` (jamais commités, jamais dans
  les rapports). Le partage opencode est désactivé pour éviter toute fuite de données.
- Conserver une trace horodatée des commandes et des preuves brutes ; ne jamais modifier
  un fichier de preuve brut.

## Architecture agentique

- `orchestrator` (primaire) : planifie, maintient `tracking.json`, délègue, contrôle les
  gates de revue et rend compte à l'utilisateur.
- `dev` (sous-agent) : implémente les scripts, tests et artefacts techniques.
- `reviewer` (sous-agent) : revue indépendante, tests d'acceptation, validation des CVE
  et du mapping MITRE, verdict PASS / CHANGES_REQUIRED / BLOCKED.
- Skills : `common` (règles partagées), `orchestrator` (protocole de pilotage), `dev`
  (standards de développement), `reviewer` (grille de revue), `recon` (méthodologie de
  reconnaissance), `mitre` (mapping et schéma du plan), `report` (rapport PDF).

Règle de passation : un sous-agent ne clôture jamais une tâche. Le `dev` rend un paquet
de revue, l'orchestrateur lance le `reviewer`, puis traite le verdict. Aucun livrable
n'est déclaré terminé sans verdict `PASS`.

## Workflow et gates

1. **Cadrage** — valider la cible, le périmètre, les livrables et les critères
   d'acceptation ; initialiser `tracking.json`.
2. **Environnement** — dépendances Python, outils système (nmap, searchsploit, pandoc ou
   weasyprint), arborescence de travail.
3. **Reconnaissance** — script paramétrable, exécution sur la cible, preuves brutes et
   normalisées.
4. **Corrélation CVE** — mapping service/version → CVE avec niveau de confiance et
   sources vérifiables.
5. **Plan MITRE** — plan d'attaque JSON + Markdown cohérents, techniques ATT&CK valides.
6. **Documentation** — rapport Markdown source et PDF final.
7. **Revue finale** — vérification des livrables, de la reproductibilité et des preuves.
8. **Clôture** — synthèse utilisateur, risques résiduels, prochaines étapes.

Chaque phase passe par une revue indépendante. Si le verdict est `CHANGES_REQUIRED`,
l'orchestrateur crée une tâche de correction avec les findings du reviewer.

## Arborescence de travail

```
scripts/recon/          scripts/cve/          scripts/report/
tests/unit/             tests/integration/    tests/e2e/
configs/                data/                 evidence/raw/
evidence/normalized/    plans/                reports/
review/                 .opencode/
```

Créer les dossiers au besoin. Les scripts vont dans `scripts/`, les tests dans `tests/`,
les preuves brutes dans `evidence/raw/`, les données normalisées dans `data/`, les plans
dans `plans/`, les rapports dans `reports/`, les revues dans `review/`.

## Conventions

- Python 3.11+, environnement virtuel `.venv`, dépendances déclarées dans
  `requirements.txt`.
- Identifiants de code en anglais ; docstrings, commentaires et documentation en
  français. Commenter les décisions non évidentes (le « pourquoi », pas le « quoi »).
- JSON valide en UTF-8, indentation 2 espaces, sans commentaires. Horodatages ISO 8601
  UTC (`YYYY-MM-DDTHH:MM:SSZ`).
- Noms de fichiers en `kebab-case`. Identifiants de tâche `T01`, `T02`, ...
- Scripts non interactifs, testables, paramétrables (`--target`, `--output`,
  `--dry-run`, `--timeout`) et sans IP codée en dur.
- Les tests unitaires ne doivent pas dépendre du lab (mock/reseau désactivé) ; les tests
  d'intégration et de bout en bout sont marqués et exécutés explicitement.
- Toujours vérifier les identifiants CVE et MITRE auprès d'une source autoritative ; ne
  jamais inventer une référence.
- Ne pas écrire dans `review/` en dehors du reviewer, ni modifier les preuves brutes.

## Definition of done

Une tâche est terminée seulement si :

- tous les critères d'acceptation sont satisfaits ;
- les tests requis passent et leurs commandes sont documentées ;
- les artefacts attendus existent aux chemins prévus ;
- le reviewer a rendu un verdict `PASS` ;
- `tracking.json` est à jour (statut, artefacts, verdict, horodatage) ;
- les risques résiduels et limites sont consignés.

## Commandes

- `/mission [ip]` : lance ou reprend le workflow complet.
- `/status` : résume `tracking.json` et propose la prochaine action.

Après toute modification de `opencode.json`, d'un agent, d'une skill ou d'une commande,
redémarrer opencode : la configuration est chargée une seule fois au démarrage.
