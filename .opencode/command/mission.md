---
description: "Lance ou reprend la mission complète : cadrage, reconnaissance, CVE, plan MITRE et rapport PDF."
agent: orchestrator
---

Charge les skills `common` et `orchestrator`, puis lis `CONTEXT.md`, `AGENTS.md` et
`tracking.json`.

Argument fourni : `$ARGUMENTS`

Déroule le workflow par étapes, avec une revue indépendante après chaque phase :

1. cadrage et confirmation de l'IP cible ;
2. préparation de l'environnement ;
3. script et exécution de la reconnaissance ;
4. corrélation CVE ;
5. plan d'attaque MITRE JSON + Markdown ;
6. rapport Markdown + PDF ;
7. revue finale et synthèse.

Si l'IP cible est absente, demande-la explicitement avant tout scan. Ne lance aucune
action intrusive ou destructive sans confirmation utilisateur. Tiens `tracking.json` à
jour après chaque transition et termine par un état d'avancement, les livrables produits
avec leurs chemins, les verdicts de revue, les risques résiduels et la prochaine action.
