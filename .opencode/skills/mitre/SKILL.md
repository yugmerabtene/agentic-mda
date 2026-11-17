---
name: mitre
description: "Mapping et schéma du plan d'attaque MITRE ATT&CK : tactiques, techniques, préconditions, preuves, risques et cohérence JSON/Markdown. À charger pour produire ou vérifier plans/attack-plan.json et plans/attack-plan.md."
---

# Plan d'attaque MITRE ATT&CK

## Principes

- Le plan décrit une campagne de laboratoire autorisée sur la cible confirmée, pas une
  cible réelle. Chaque étape doit être justifiée par un service ou une CVE observée.
- Ne citer que des techniques ATT&CK existantes, avec leur identifiant exact.
- Ne jamais inventer une technique pour « remplir » une tactique.
- Vérifier les identifiants sur <https://attack.mitre.org/> et consigner la version de la
  matrice utilisée.
- Une étape destructive ou hors périmètre reste conditionnée à une confirmation explicite
  de l'utilisateur et à une condition d'arrêt.

## Tactiques de référence

| Tactique | ID |
|----------|----|
| Reconnaissance | TA0043 |
| Resource Development | TA0042 |
| Initial Access | TA0001 |
| Execution | TA0002 |
| Persistence | TA0003 |
| Privilege Escalation | TA0004 |
| Defense Evasion | TA0005 |
| Credential Access | TA0006 |
| Discovery | TA0007 |
| Lateral Movement | TA0008 |
| Collection | TA0009 |
| Command and Control | TA0011 |
| Exfiltration | TA0010 |
| Impact | TA0040 |

## Techniques fréquentes en lab

| Technique | ID | Usage typique |
|-----------|----|---------------|
| Active Scanning | T1595 | nmap, découverte de ports |
| Vulnerability Scanning | T1595.002 | corrélation CVE |
| Network Service Discovery | T1046 | énumération de services |
| Remote System Discovery | T1018 | découverte d'hôtes |
| Exploit Public-Facing Application | T1190 | service HTTP exposé |
| Exploitation of Remote Services | T1210 | service réseau vulnérable |
| Valid Accounts | T1078 | comptes par défaut (après accord) |
| Brute Force | T1110 | uniquement avec autorisation |
| Command and Scripting Interpreter | T1059 | exécution de commandes |
| OS Credential Dumping | T1003 | post-exploitation autorisée |
| Remote Services: SSH | T1021.004 | accès distant |
| Remote Services: VNC | T1021.005 | accès distant |
| Ingress Tool Transfer | T1105 | transfert d'outils |
| Indicator Removal | T1070 | nettoyage (si autorisé) |
| Application Layer Protocol | T1071 | canal de commande |

Toute autre technique doit être vérifiée avant usage.

## Schéma `plans/attack-plan.json`

```json
{
  "schema_version": "1.0",
  "mission": "Lab Metasploitable",
  "target": { "ip": "192.168.56.10", "name": "Metasploitable" },
  "generated_at": "YYYY-MM-DDTHH:MM:SSZ",
  "attack_version": "vXX (version vérifiée sur attack.mitre.org)",
  "authorization": {
    "scope": "lab local uniquement",
    "confirmed_by": "utilisateur",
    "confirmed_at": "YYYY-MM-DDTHH:MM:SSZ"
  },
  "phases": [
    {
      "id": "P1",
      "name": "Reconnaissance",
      "tactic": { "id": "TA0043", "name": "Reconnaissance" },
      "steps": [
        {
          "id": "S1.1",
          "objective": "Identifier les services exposés",
          "technique": { "id": "T1595.002", "name": "Vulnerability Scanning" },
          "services": ["21/tcp", "80/tcp"],
          "cves": ["CVE-YYYY-NNNN"],
          "tools": ["nmap"],
          "preconditions": ["IP cible confirmée", "autorisation lab"],
          "command": "nmap -Pn -sV ...",
          "expected_evidence": "evidence/raw/service-....xml",
          "detection": ["Journaux de pare-feu", "alertes IDS"],
          "risk": "low",
          "stop_conditions": ["cible inattendue", "service hors périmètre"],
          "requires_user_approval": false
        }
      ]
    }
  ],
  "preconditions": [],
  "assumptions": [],
  "stop_conditions": [],
  "references": []
}
```

Champs obligatoires par étape : id, objective, technique.id, technique.name, tools,
preconditions, expected_evidence, risk, stop_conditions, requires_user_approval.

## Règles de cohérence

- Chaque CVE citée doit exister dans `data/cves.json`.
- Chaque service cité doit exister dans `data/services.json`.
- Les identifiants d'étape sont uniques et ordonnés.
- Les tactiques se succèdent de façon logique : reconnaissance → accès → exécution →
  découverte → élévation → mouvement → objectif, sans saut incohérent.
- Les étapes `requires_user_approval: true` ne sont pas exécutées sans accord consigné.
- Le Markdown `plans/attack-plan.md` reprend exactement les mêmes étapes, IDs, techniques
  et CVE que le JSON.
- Les risques et conditions d'arrêt sont explicites ; pas de « impact inconnu » sans
  justification.

## Validation automatisée attendue

Un script de vérification doit au minimum :

- valider le JSON contre le schéma ;
- vérifier l'unicité des IDs ;
- vérifier le format `Txxxx(.xxx)` et la présence des tactiques ;
- croiser les CVE avec `data/cves.json` ;
- croiser les services avec `data/services.json` ;
- vérifier la correspondance JSON ↔ Markdown ;
- retourner un code non nul en cas d'erreur.

## Restitution

- Plan JSON : `plans/attack-plan.json`.
- Plan lisible : `plans/attack-plan.md` avec tableau par phase, préconditions, risques,
  preuves attendues et conditions d'arrêt.
- Mention explicite : laboratoire local, aucune action hors périmètre, pas d'exploitation
  sans autorisation.
