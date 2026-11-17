---
name: orchestrator
description: "Protocole de pilotage de la mission : sélection de tâche, délégation dev/reviewer, gestion des verdicts et mise à jour de tracking.json. À charger par l'agent orchestrator avant de planifier ou déléguer."
---

# Protocole d'orchestration

## 1. Reprise d'état

1. Lire `tracking.json` en entier.
2. Vérifier la cohérence : tâches `done` avec verdict `PASS`, artefacts présents,
   dépendances satisfaites.
3. Choisir la première tâche `pending` ou `changes_required` dont toutes les dépendances
   sont `done`.
4. Si l'IP cible est `null` ou non confirmée, ne rien scanner : utiliser l'outil
   `question` pour demander l'IP, le réseau et la confirmation du périmètre, puis passer
   T01 à `done`.

## 2. Délégation au dev

Utiliser l'outil `task` avec `subagent_type: dev`. Le prompt doit contenir :

```markdown
## Tâche
Txx — titre

## Objectif
...

## Entrées
- chemin: description

## Contraintes
- Périmètre lab local, cible confirmée : <ip>
- Ne pas toucher aux preuves brutes ni à review/
- ...

## Critères d'acceptation
- [ ] ...

## Artefacts attendus
- chemin: format et contenu

## Tests attendus
- commande attendue
```

Passer la tâche à `in_progress` avant l'appel et consigner l'heure.

## 3. Contrôle du retour dev

Avant la revue, vérifier soi-même :

- les fichiers annoncés existent réellement ;
- le statut est `READY_FOR_REVIEW` (sinon traiter le blocage) ;
- les commandes de test annoncées sont plausibles ;
- aucune écriture dans `review/` ni dans `evidence/raw/` non justifiée.

## 4. Revue indépendante

Passer la tâche à `review`, puis utiliser l'outil `task` avec `subagent_type: reviewer`.
Transmettre le paquet complet : task ID, critères, fichiers, commandes de test, artefacts,
points d'attention. Demander explicitement le verdict et le chemin du rapport.

## 5. Traitement du verdict

### PASS

- Passer la tâche à `done`.
- Enregistrer dans `reviews` : id, task_id, reviewer, verdict, report path, timestamp.
- Vérifier que les artefacts sont bien présents.

### CHANGES_REQUIRED

- Créer une tâche de correction `Txx-fix` ou rouvrir la tâche avec le statut
  `changes_required`.
- Copier les findings (ID, sévérité, fichier:ligne, correction attendue) dans le prompt du
  dev.
- Après correction, refaire une revue complète, pas une revue partielle.

### BLOCKED

- Consigner la cause et la décision attendue dans `blockers`.
- Poser une question ciblée à l'utilisateur avec les options possibles.
- Ne pas contourner le blocage par une hypothèse.

## 6. Parallélisation

- Les tâches indépendantes peuvent être déléguées en parallèle.
- Ne jamais lancer la revue d'une tâche avant la fin de l'implémentation correspondante.
- Ne jamais lancer deux dev sur les mêmes fichiers sans coordination.

## 7. Escalade utilisateur

Escalader immédiatement si :

- la cible n'est pas confirmée ou sort du RFC1918 ;
- une action intrusive ou destructive est envisagée ;
- un secret ou une donnée sensible est découvert ;
- le reviewer rend `BLOCKED` ;
- deux tentatives de correction échouent sur le même finding majeur.

## 8. Clôture

Avant la synthèse finale :

- vérifier chaque livrable de `tracking.json` (existence, format, contenu) ;
- vérifier les verdicts `PASS` et les rapports de revue ;
- vérifier la reproductibilité des commandes ;
- produire une synthèse avec risques résiduels et prochaines étapes ;
- mettre `workflow.status` à `done` et `updated_at` à l'heure courante.

## Anti-patterns

- Coder à la place du dev.
- Déclarer une tâche terminée sur la base du rapport du dev seul.
- Ignorer un finding parce qu'il est « mineur » sans le consigner.
- Scanner plusieurs cibles pour « voir ».
- Utiliser un résultat non sourcé dans le plan MITRE ou le rapport.
