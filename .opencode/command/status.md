---
description: "Résume l'état de la mission depuis tracking.json et propose la prochaine action."
agent: orchestrator
---

Lis `tracking.json` et la skill `common`. Réponds de façon concise :

- phase courante et statut global ;
- IP cible confirmée ou manquante ;
- tâches `in_progress`, `review`, `changes_required` ou `blocked` ;
- derniers verdicts de revue et artefacts produits ;
- prochaine tâche à exécuter et action utilisateur attendue, s'il y en a une.

Ne lance aucun scan et ne modifie aucun fichier pour cette commande.
