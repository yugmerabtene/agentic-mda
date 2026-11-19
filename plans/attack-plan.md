# Plan d'attaque MITRE ATT&CK — Lab Metasploitable

**Cible :** 192.168.56.103 (Metasploitable2, réseau 192.168.56.0/24, RFC1918)
**Version de la matrice ATT&CK :** v20.1 (vérifiée sur https://attack.mitre.org le 2026-11-19)
**Généré le :** 2026-11-19T12:08:33Z
**Source de vérité :** `plans/attack-plan.json` (ce document en est la restitution lisible)

## Périmètre et autorisation

- Ce plan s'applique **uniquement** à la cible locale 192.168.56.103 sur le réseau lab
  192.168.56.0/24 (RFC1918). Aucune cible publique, aucun domaine tiers, aucun actif hors
  lab n'est visé.
- Aucune action intrusive (exploitation, force brute, déni de service, mouvement latéral,
  élévation de privilèges) n'est exécutée dans le cadre de ce livrable : le plan est
  **préparatoire et documentaire**.
- Toute étape marquée `requires_user_approval: true` nécessite un accord utilisateur
  explicite et consigné avant exécution.
- Les étapes destructrices (impact sur la disponibilité) restent conditionnées à une
  confirmation explicite de l'utilisateur et à une condition d'arrêt.

## Sommaire des phases

| Phase | ID | Tactic ATT&CK | Étapes | Cibles de services | CVE associées |
|-------|----|---------------|--------|--------------------|---------------|
| P1 — Reconnaissance | TA0043 | Reconnaissance | S1.1 | 21, 22, 23, 25, 80, 111, 139, 445, 512, 513, 514/tcp | 20 CVE |
| P2 — Initial Access | TA0001 | Initial Access | S2.1, S2.2, S2.3, S2.4 | 80, 21, 139/445, 23/tcp | 10 CVE |
| P3 — Execution | TA0002 | Execution | S3.1 | 21, 139, 445/tcp | CVE-2011-2523, CVE-2007-2447 |
| P4 — Privilege Escalation | TA0004 | Privilege Escalation | S4.1 | 139, 445/tcp | CVE-2007-2444, CVE-2009-1888, CVE-2010-0728, CVE-2010-0926 |
| P5 — Credential Access | TA0006 | Credential Access | S5.1 | 22/tcp | CVE-2008-5161 |
| P6 — Lateral Movement | TA0008 | Lateral Movement | S6.1 | 22/tcp | CVE-2008-5161 |
| P7 — Collection | TA0009 | Collection | S7.1 | 25/tcp | CVE-2005-0337, CVE-2023-51764 |
| P8 — Impact | TA0040 | Impact | S8.1, S8.2 | 139/445, 23/tcp | CVE-2007-0452, CVE-2008-4314, CVE-2009-2906, CVE-2022-39028 |

**Total : 12 étapes, 8 techniques ATT&CK uniques, 20 CVE de `data/cves.json` citées.**

Les services sans CVE associée (111/tcp rpcbind, 512/tcp exec, 513/tcp login,
514/tcp shell) apparaissent uniquement en reconnaissance (P1) ; ils ne font l'objet
d'aucune étape d'exploitation dans ce plan.

---

## Phase P1 — Reconnaissance (TA0043)

### S1.1 — Vulnerability Scanning (T1595.002)

- **Objectif :** Détecter les services et leurs versions exposés sur la cible, puis
  corréler avec les CVE connues (données de T05/T07).
- **Services :** 21/tcp, 22/tcp, 23/tcp, 25/tcp, 80/tcp, 111/tcp, 139/tcp, 445/tcp,
  512/tcp, 513/tcp, 514/tcp
- **CVE :** toutes les 20 CVE de `data/cves.json`
- **Outils :** nmap
- **Préconditions :**
  - Cible 192.168.56.103 confirmée dans `tracking.json` (réseau RFC1918) ;
  - Autorisation lab valide, périmètre reconnaissance uniquement.
- **Commande (modèle) :** `nmap -Pn -sV -p- --open <target> -oX evidence/raw/nmap-<target>-<timestamp_utc>.xml`
- **Preuves attendues :**
  - `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml`
  - `data/services.json`
  - `data/cves.json`
- **Détection :** journaux de pare-feu/hôte (scans de ports) ; alertes IDS sur activité
  de scan de vulnérabilités.
- **Risque :** low
- **Conditions d'arrêt :** cible inattendue ou hors périmètre ; service non listé dans
  `data/services.json`.
- **Approbation utilisateur requise :** non

---

## Phase P2 — Initial Access (TA0001)

### S2.1 — Exploit Public-Facing Application (T1190) — Apache httpd 2.2.8 (80/tcp)

- **Objectif :** Accéder au serveur web via une application publique exposée.
- **Services :** 80/tcp
- **CVE :** CVE-1999-0236, CVE-2005-3630, CVE-2006-4625
- **Outils :** searchsploit, navigateur web / client HTTP
- **Préconditions :** phase P1 terminée, service 80/tcp confirmé ; accord utilisateur
  explicite pour action intrusive.
- **Commande (modèle) :** `searchsploit --json apache 2.2.8 ; vérification manuelle sur la cible uniquement si approuvé`
- **Preuves attendues :** `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` ;
  entrées CVE-1999-0236, CVE-2005-3630, CVE-2006-4625 de `data/cves.json`.
- **Détection :** journaux Apache (access.log/error.log) requêtes anomales ; alertes
  WAF/IDS sur exploitation d'application web.
- **Risque :** high
- **Conditions d'arrêt :** service 80/tcp indisponible ou version différente ; absence
  d'accord utilisateur.
- **Approbation utilisateur requise :** oui

### S2.2 — Exploitation of Remote Services (T1210) — vsftpd 2.3.4 (21/tcp)

- **Objectif :** Exploiter le service FTP vsftpd 2.3.4 contenant une porte-arrière
  ouvrant un shell sur 6200/tcp.
- **Services :** 21/tcp
- **CVE :** CVE-2011-2523
- **Outils :** searchsploit, netcat
- **Préconditions :** phase P1 terminée, service 21/tcp vsftpd 2.3.4 confirmé ; accord
  utilisateur explicite.
- **Commande (modèle) :** `searchsploit --json vsftpd 2.3.4 ; connexion sur 6200/tcp uniquement si approuvé`
- **Preuves attendues :** `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` ;
  entrée CVE-2011-2523 de `data/cves.json`.
- **Détection :** connexion entrante inattendue sur 6200/tcp ; journaux vsftpd/xinetd.
- **Risque :** critical
- **Conditions d'arrêt :** version vsftpd différente de 2.3.4 ; absence d'accord
  utilisateur.
- **Approbation utilisateur requise :** oui

### S2.3 — Exploitation of Remote Services (T1210) — Samba smbd (139/tcp, 445/tcp)

- **Objectif :** Exploiter les services SMB/CIFS Samba via MS-RPC pour exécuter du code
  à distance.
- **Services :** 139/tcp, 445/tcp
- **CVE :** CVE-2007-2446, CVE-2007-2447
- **Outils :** searchsploit, smbclient
- **Préconditions :** phase P1 terminée, services 139/tcp et 445/tcp Samba confirmés ;
  accord utilisateur explicite.
- **Commande (modèle) :** `searchsploit --json samba 3.x ; vérification des appels MS-RPC uniquement si approuvé`
- **Preuves attendues :** `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` ;
  entrées CVE-2007-2446, CVE-2007-2447 de `data/cves.json`.
- **Détection :** journaux Samba (log.smbd) requêtes MS-RPC anomales ; alertes IDS sur
  exploitation SMB.
- **Risque :** high
- **Conditions d'arrêt :** version Samba hors plage affectée (3.0.0–3.0.25rc3) ; absence
  d'accord utilisateur.
- **Approbation utilisateur requise :** oui

### S2.4 — Exploitation of Remote Services (T1210) — telnetd (23/tcp)

- **Objectif :** Accéder via le service telnetd : contournement d'authentification ou
  dégradation de service.
- **Services :** 23/tcp
- **CVE :** CVE-2000-1195, CVE-2020-8797, CVE-2021-27171, CVE-2022-39028
- **Outils :** searchsploit, client telnet
- **Préconditions :** phase P1 terminée, service 23/tcp telnetd confirmé ; accord
  utilisateur explicite.
- **Commande (modèle) :** `searchsploit --json telnetd ; tentative uniquement si approuvé`
- **Preuves attendues :** `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` ;
  entrées CVE-2000-1195, CVE-2020-8797, CVE-2021-27171, CVE-2022-39028 de
  `data/cves.json`.
- **Détection :** journaux telnetd/inetd échecs ou boucles de connexion ; alertes IDS
  sur trafic telnet anormal.
- **Risque :** high
- **Conditions d'arrêt :** service 23/tcp indisponible ; absence d'accord utilisateur.
- **Approbation utilisateur requise :** oui

---

## Phase P3 — Execution (TA0002)

### S3.1 — Command and Scripting Interpreter (T1059)

- **Objectif :** Exécuter des commandes sur la cible via le shell obtenu (porte-arrière
  vsftpd ou script de noms d'utilisateur Samba).
- **Services :** 21/tcp, 139/tcp, 445/tcp
- **CVE :** CVE-2011-2523, CVE-2007-2447
- **Outils :** shell distant, interpréteur de commandes
- **Préconditions :** accès initial obtenu (P2 S2.2 ou S2.3 réussi) ; accord utilisateur
  explicite pour exécution de commandes.
- **Commande (modèle) :** exécution de commandes via le shell obtenu (à définir selon
  l'accès réussi)
- **Preuves attendues :** `data/cves.json` (entrées CVE-2011-2523, CVE-2007-2447) ;
  compte-rendu de session si autorisé.
- **Détection :** processus shells inattendus sur la cible ; journaux d'exécution de
  commandes.
- **Risque :** high
- **Conditions d'arrêt :** perte de l'accès distant ; absence d'accord utilisateur.
- **Approbation utilisateur requise :** oui

---

## Phase P4 — Privilege Escalation (TA0004)

### S4.1 — Exploitation for Privilege Escalation (T1068) — Samba

- **Objectif :** Élever les privilèges sur la cible via les vulnérabilités Samba
  (translation SID/nom, ACL, capacités, traversal de liens symboliques).
- **Services :** 139/tcp, 445/tcp
- **CVE :** CVE-2007-2444, CVE-2009-1888, CVE-2010-0728, CVE-2010-0926
- **Outils :** searchsploit, client SMB
- **Préconditions :** accès utilisateur sur la cible (P3 réussi) ; accord utilisateur
  explicite pour élévation de privilèges.
- **Commande (modèle) :** `searchsploit --json samba privilege escalation ; exploitation uniquement si approuvé`
- **Preuves attendues :** `data/cves.json` (entrées CVE-2007-2444, CVE-2009-1888,
  CVE-2010-0728, CVE-2010-0926).
- **Détection :** changements de compte/privilèges dans les journaux Samba et système ;
  alertes EDR sur élévation de privilèges.
- **Risque :** high
- **Conditions d'arrêt :** version Samba non vulnérable ; absence d'accord utilisateur.
- **Approbation utilisateur requise :** oui

---

## Phase P5 — Credential Access (TA0006)

### S5.1 — Brute Force (T1110) — OpenSSH 4.7p1 (22/tcp)

- **Objectif :** Tenter l'accès aux identifiants via le service SSH : force brute sur
  comptes faibles et analyse du chiffrement CBC (CVE-2008-5161).
- **Services :** 22/tcp
- **CVE :** CVE-2008-5161
- **Outils :** searchsploit, outil de force brute (à définir)
- **Préconditions :** phase P1 terminée, service 22/tcp OpenSSH 4.7p1 confirmé ; accord
  utilisateur explicite pour force brute.
- **Commande (modèle) :** `searchsploit --json openssh 4.7 ; force brute uniquement si approuvé et avec liste de mots de passe restreinte`
- **Preuves attendues :** `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` ;
  entrée CVE-2008-5161 de `data/cves.json`.
- **Détection :** journaux SSH (auth.log) échecs d'authentification répétés ; alertes
  IDS sur force brute SSH.
- **Risque :** medium
- **Conditions d'arrêt :** verrouillage de compte détecté ; absence d'accord utilisateur.
- **Approbation utilisateur requise :** oui

---

## Phase P6 — Lateral Movement (TA0008)

### S6.1 — Remote Services: SSH (T1021.004)

- **Objectif :** Se déplacer latéralement vers la cible via le service SSH avec des
  identifiants obtenus.
- **Services :** 22/tcp
- **CVE :** CVE-2008-5161
- **Outils :** client SSH
- **Préconditions :** identifiants valides obtenus (P5 réussi) ; accord utilisateur
  explicite pour mouvement latéral.
- **Commande (modèle) :** `ssh <utilisateur>@<target> uniquement si approuvé`
- **Preuves attendues :** `data/cves.json` (entrée CVE-2008-5161).
- **Détection :** journaux SSH connexions entrantes/sortantes anormales ; alertes sur
  mouvement latéral SSH.
- **Risque :** medium
- **Conditions d'arrêt :** identifiants refusés ; absence d'accord utilisateur.
- **Approbation utilisateur requise :** oui

---

## Phase P7 — Collection (TA0009)

### S7.1 — Exploit Public-Facing Application (T1190) — Postfix smtpd (25/tcp)

- **Objectif :** Interagir avec le service SMTP Postfix : relais de courrier et
  contournement SPF via SMTP smuggling.
- **Services :** 25/tcp
- **CVE :** CVE-2005-0337, CVE-2023-51764
- **Outils :** searchsploit, client SMTP
- **Préconditions :** phase P1 terminée, service 25/tcp Postfix confirmé ; accord
  utilisateur explicite pour interaction avec le service mail.
- **Commande (modèle) :** `searchsploit --json postfix ; test SMTP uniquement si approuvé`
- **Preuves attendues :** `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` ;
  entrées CVE-2005-0337, CVE-2023-51764 de `data/cves.json`.
- **Détection :** journaux Postfix (mail.log) relais ou messages anomales ; alertes sur
  SMTP smuggling.
- **Risque :** medium
- **Conditions d'arrêt :** service 25/tcp indisponible ; absence d'accord utilisateur.
- **Approbation utilisateur requise :** oui

---

## Phase P8 — Impact (TA0040)

### S8.1 — Endpoint Denial of Service (T1499) — Samba (139/tcp, 445/tcp)

- **Objectif :** Dégrader la disponibilité des services Samba par déni de service
  (boucle infinie, lecture mémoire, crash).
- **Services :** 139/tcp, 445/tcp
- **CVE :** CVE-2007-0452, CVE-2008-4314, CVE-2009-2906
- **Outils :** searchsploit, client SMB
- **Préconditions :** phase P1 terminée, services Samba confirmés ; accord utilisateur
  explicite pour action destructive (disponibilité).
- **Commande (modèle) :** `searchsploit --json samba denial of service ; test DoS uniquement si approuvé`
- **Preuves attendues :** `data/cves.json` (entrées CVE-2007-0452, CVE-2008-4314,
  CVE-2009-2906).
- **Détection :** indisponibilité des partages SMB ; journaux Samba crash/boucle,
  alertes disponibilité.
- **Risque :** high
- **Conditions d'arrêt :** impact sur la disponibilité au-delà du périmètre accepté ;
  absence d'accord utilisateur.
- **Approbation utilisateur requise :** oui

### S8.2 — Endpoint Denial of Service (T1499) — telnetd (23/tcp)

- **Objectif :** Dégrader la disponibilité du service telnetd par déréférencement NULL
  (crash du démon).
- **Services :** 23/tcp
- **CVE :** CVE-2022-39028
- **Outils :** searchsploit, client telnet
- **Préconditions :** phase P1 terminée, service 23/tcp telnetd confirmé ; accord
  utilisateur explicite pour action destructive (disponibilité).
- **Commande (modèle) :** `searchsploit --json telnetd NULL pointer ; test DoS uniquement si approuvé`
- **Preuves attendues :** `data/cves.json` (entrée CVE-2022-39028).
- **Détection :** arrêt du démon telnetd, journaux inetd (boucle de service terminée) ;
  alertes disponibilité sur 23/tcp.
- **Risque :** high
- **Conditions d'arrêt :** service 23/tcp déjà indisponible ; absence d'accord
  utilisateur.
- **Approbation utilisateur requise :** oui

---

## Préconditions globales

1. Cible 192.168.56.103 confirmée par l'utilisateur et consignée dans `tracking.json`.
2. Réseau lab privé RFC1918 (192.168.56.0/24) uniquement.
3. Preuves de reconnaissance disponibles : `evidence/raw/nmap-*.xml`,
   `data/services.json`, `data/cves.json`.
4. Aucune action intrusive sans accord utilisateur explicite consigné.

## Hypothèses

- Les versions de services dans `data/services.json` proviennent du scan nmap de T05.
- Les CVE de `data/cves.json` sont vérifiées sur la NVD (source `nvd`) avec un niveau
  de confiance associé.
- Les faux positifs signalés dans `data/cves.json` sont exclus du plan d'exploitation.
- Les services sans CVE (111/tcp rpcbind, 512/tcp exec, 513/tcp login, 514/tcp shell)
  ne sont pas cibles d'exploitation dans ce plan.

## Conditions d'arrêt globales

1. Cible ou service hors périmètre lab (non 192.168.56.103 / 192.168.56.0/24).
2. Absence d'accord utilisateur pour toute étape `requires_user_approval: true`.
3. Détection d'une réaction défensive bloquante (IDS/IPS, verrouillage de compte).
4. Version de service différente de celle référencée dans `data/cves.json`.

## Références

- https://attack.mitre.org/ (MITRE ATT&CK, version v20.1 vérifiée le 2026-11-19)
- https://nvd.nist.gov/ (National Vulnerability Database, source des CVE de
  `data/cves.json`)
- `data/services.json` (inventaire des services, T05)
- `data/cves.json` (corrélation CVE, T07)
- `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` (preuve brute de
  reconnaissance)

## Cohérence JSON ↔ Markdown

Ce document reprend exactement les mêmes phases, IDs d'étapes (`S1.1` … `S8.2`),
techniques ATT&CK (IDs `Txxxx` et noms), services et CVE que
`plans/attack-plan.json`. Toute modification doit être appliquée aux deux fichiers.
