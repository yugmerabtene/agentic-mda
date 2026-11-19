# Rapport final de mission — Lab Metasploitable

**Titre :** Reconnaissance, corrélation CVE, plan d'attaque MITRE ATT&CK et documentation d'une VM Metasploitable  
**Auteur :** équipe projet agentique (rôle `dev`)  
**Date du rapport :** 2026-11-19  
**Version :** 1.0  
**Classification :** lab local — usage interne uniquement  
**Cible :** 192.168.56.103 (Metasploitable2, réseau 192.168.56.0/24, RFC1918)  
**Statut :** livrable final — prêt pour revue indépendante (T12)

---

## 1. Résumé exécutif

Cette mission a consisté à réaliser, sur une VM Metasploitable2 située en laboratoire local, une reconnaissance réseau automatisée, la corrélation des services découverts avec des vulnérabilités CVE vérifiables, la production d'un plan d'attaque MITRE ATT&CK (JSON + Markdown) et la rédaction du présent rapport final.

**Cible unique :** `192.168.56.103` sur le réseau `192.168.56.0/24` (RFC1918, périmètre lab confirmé par l'utilisateur et consigné dans `tracking.json`).

**Résultats clés :**

| Indicateur | Valeur | Source |
|------------|--------|--------|
| Ports TCP ouverts découverts | 11 | `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` |
| Services inventoriés | 11 | `data/services.json` |
| CVE corrélées | 20 | `data/cves.json` |
| CVE de sévérité CRITICAL | 2 (CVE-2011-2523, CVE-2021-27171) | `data/cves.json` |
| CVE de sévérité HIGH | 8 | `data/cves.json` |
| Techniques MITRE ATT&CK uniques | 8 | `plans/attack-plan.json` |
| Phases du plan d'attaque | 8 (P1 à P8) | `plans/attack-plan.json` |
| Étapes du plan d'attaque | 12 (S1.1 à S8.2) | `plans/attack-plan.json` |
| Revues indépendantes | 8 (R-001 à R-008, toutes PASS) | `review/` |

**Risque majeur :** le service FTP `vsftpd 2.3.4` (21/tcp) est affecté par `CVE-2011-2523` (porte-arrière ouvrant un shell sur 6200/tcp, CVSS 9.8, confiance `high`). Ce service présente le risque d'accès initial le plus élevé du lab.

**Aucune action intrusive n'a été exécutée** dans le cadre de cette mission : reconnaissance seule, plan préparatoire et documentaire. Toute étape d'exploitation, force brute, élévation de privilèges, mouvement latéral ou déni de service est conditionnée à un accord utilisateur explicite et consigné (`requires_user_approval: true` dans le plan MITRE).

---

## 2. Périmètre et autorisation

- **Cible autorisée :** `192.168.56.103` uniquement (VM Metasploitable2).
- **Réseau lab :** `192.168.56.0/24` (RFC1918, réseau privé virtuel host-only VirtualBox, interface `vboxnet0`).
- **Périmètre des actions :** reconnaissance (scan nmap non intrusif avec détection de versions) + plan d'attaque préparatoire. Aucune exploitation, force brute, modification de service, persistance ou exfiltration n'a été réalisée.
- **Confirmation cible :** IP et réseau confirmés par l'utilisateur, consignés dans `tracking.json` (décision D-001 et correction D-003 : l'IP cible est 192.168.56.103, 192.168.56.101 étant la machine Kali attaquante).
- **Règle de sécurité :** toute action intrusive nécessite une confirmation explicite de l'utilisateur, même en lab. Aucune confirmation n'a été sollicitée ni obtenue pour une action intrusive dans cette tâche T11.
- **Aucune cible publique, aucun domaine tiers, aucun actif hors lab n'a été visé.**

---

## 3. Environnement et méthodologie

### 3.1 Environnement technique

| Élément | Version / valeur |
|---------|------------------|
| Système hôte | Linux |
| Hyperviseur | VirtualBox 7.1.18 |
| Réseau lab | `vboxnet0`, `192.168.56.1/24`, DHCP désactivé |
| Interpréteur Python | 3.12.3 (environnement virtuel `.venv`) |
| Générateur de rapport | weasyprint 70.0 (depuis `.venv`) |
| Outil de reconnaissance | nmap 7.94SVN |
| Validation JSON | jsonschema 4.23.0 |
| Tests | pytest 8.3.3 |
| Lintage | ruff 0.9.2 |
| pandoc | absent (non requis, weasyprint utilisé) |
| searchsploit | absent (non installé, non requis pour ce livrable) |

### 3.2 Chaîne de génération du rapport

Le rapport est produit selon la chaîne suivante, entièrement documentée pour reproductibilité :

1. Rédaction de la source Markdown : `reports/rapport-final.md`.
2. Conversion Markdown → HTML par le script `scripts/report/generate_report.py` (convertisseur dédié, aucune dépendance externe supplémentaire).
3. Rendu HTML → PDF par weasyprint 70.0.
4. Vérification du PDF : `pdftotext` et `pdfinfo`.

**Commande de génération (exécutée) :**

```bash
source /home/yug/Documents/agentic/.venv/bin/activate
python3 /home/yug/Documents/agentic/scripts/report/generate_report.py \
  --source /home/yug/Documents/agentic/reports/rapport-final.md \
  --output /home/yug/Documents/agentic/reports/rapport-final.pdf
```

**Résultat :** PDF généré avec succès (voir section Preuves et section 11 pour l'empreinte et le nombre de pages).

Aucune IP n'est codée en dur dans le script de génération : il prend `--source` et `--output` en arguments et lit les données de cible depuis `data/services.json`, `data/cves.json` et `plans/attack-plan.json`.

### 3.3 Méthodologie

1. **Reconnaissance (T03/T05) :** scan nmap `-Pn -sT -sV --version-all` sur les ports 1-1024 de la cible, sortie XML/gnmap/nmap, preuves brutes horodatées dans `evidence/raw/`.
2. **Normalisation (T05) :** extraction des services, produits, versions et CPE depuis le XML nmap vers `data/services.json` (11 services).
3. **Corrélation CVE (T07/T08) :** requête NVD (source `nvd`) par produit/version/CPE, 20 CVE corrélées avec niveau de confiance, 12 faux positifs documentés et exclus, 3 services sans CVE correspondante.
4. **Plan MITRE ATT&CK (T09/T10) :** 8 phases, 12 étapes, 8 techniques, mapping vers les CVE de `data/cves.json`, préconditions et conditions d'arrêt documentées.
5. **Documentation (T11) :** rapport Markdown source + PDF généré, traçabilité des preuves par chemin relatif.

---

## 4. Inventaire des services

Onze (11) services TCP ouverts ont été découverts sur `192.168.56.103` lors du scan nmap du 2026-11-19T09:57:51Z. L'inventaire complet est normalisé dans `data/services.json` et tracé vers la preuve brute `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml`.

| Port | Protocole | Service | Produit | Version | CPE | Source |
|------|-----------|---------|---------|---------|-----|--------|
| 21 | tcp | ftp | vsftpd | 2.3.4 | `cpe:/a:vsftpd:vsftpd:2.3.4` | `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` |
| 22 | tcp | ssh | OpenSSH | 4.7p1 Debian 8ubuntu1 | `cpe:/a:openbsd:openssh:4.7p1`, `cpe:/o:linux:linux_kernel` | idem |
| 23 | tcp | telnet | Linux telnetd | non renseigné | `cpe:/o:linux:linux_kernel` | idem |
| 25 | tcp | smtp | Postfix smtpd | non renseigné | `cpe:/a:postfix:postfix` | idem |
| 80 | tcp | http | Apache httpd | 2.2.8 | `cpe:/a:apache:http_server:2.2.8` | idem |
| 111 | tcp | rpcbind | rpcbind | 2 | (aucun) | idem |
| 139 | tcp | netbios-ssn | Samba smbd | 3.X - 4.X | `cpe:/a:samba:samba` | idem |
| 445 | tcp | netbios-ssn | Samba smbd | 3.X - 4.X | `cpe:/a:samba:samba` | idem |
| 512 | tcp | exec | netkit-rsh rexecd | non renseigné | `cpe:/a:netkit:netkit`, `cpe:/o:linux:linux_kernel` | idem |
| 513 | tcp | login | OpenBSD or Solaris rlogind | non renseigné | (aucun) | idem |
| 514 | tcp | shell | Netkit rshd | non renseigné | `cpe:/a:netkit:netkit_rsh` | idem |

**Preuve brute :** `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` (nmap 7.94SVN, scan connect, ports 1-1024, 11,35 secondes, 1 hôte actif).  
**Empreintes SHA-256 :** `evidence/raw/manifest-192.168.56.103-20261119T095751Z.sha256` (couvre les fichiers `.nmap`, `.xml`, `.gnmap`).  
**Log de scan :** `evidence/raw/recon-192.168.56.103-20261119T095751Z.log`.

> Note (finding R-005/F-001) : le manifeste SHA-256 couvre les trois fichiers nmap (`.nmap`, `.xml`, `.gnmap`) mais omet le fichier de log `recon-....log`. Cette omission est mineure et non bloquante pour ce livrable.

---

## 5. Analyse CVE

Vingt (20) CVE ont été corrélées aux services découverts, toutes issues de la National Vulnerability Database (NVD, source `nvd`) et vérifiées sur `https://nvd.nist.gov/`. Aucune CVE n'a été inventée ou complétée de mémoire.

### 5.1 Tableau des CVE corrélées

| CVE | Service | Produit | Version | CVSS | Sévérité | Confiance | Source |
|-----|---------|---------|---------|------|----------|-----------|--------|
| CVE-2011-2523 | 21/tcp | vsftpd | 2.3.4 | 9.8 | CRITICAL | high | NVD |
| CVE-2021-27171 | 23/tcp | Linux telnetd | n/a | 9.8 | CRITICAL | medium | NVD |
| CVE-2007-2446 | 139/445/tcp | Samba smbd | 3.X-4.X | 10.0 | HIGH | medium | NVD |
| CVE-2008-4314 | 139/445/tcp | Samba smbd | 3.X-4.X | 8.5 | HIGH | medium | NVD |
| CVE-2010-0728 | 139/445/tcp | Samba smbd | 3.X-4.X | 8.5 | HIGH | medium | NVD |
| CVE-1999-0236 | 80/tcp | Apache httpd | 2.2.8 | 7.5 | HIGH | medium | NVD |
| CVE-2000-1195 | 23/tcp | Linux telnetd | n/a | 7.5 | HIGH | medium | NVD |
| CVE-2005-0337 | 25/tcp | Postfix smtpd | n/a | 7.5 | HIGH | medium | NVD |
| CVE-2007-2444 | 139/445/tcp | Samba smbd | 3.X-4.X | 7.2 | HIGH | medium | NVD |
| CVE-2022-39028 | 23/tcp | Linux telnetd | n/a | 7.5 | HIGH | medium | NVD |
| CVE-2007-0452 | 139/445/tcp | Samba smbd | 3.X-4.X | 6.8 | MEDIUM | medium | NVD |
| CVE-2007-2447 | 139/445/tcp | Samba smbd | 3.X-4.X | 6.0 | MEDIUM | medium | NVD |
| CVE-2020-8797 | 23/tcp | Linux telnetd | n/a | 6.7 | MEDIUM | medium | NVD |
| CVE-2008-5161 | 22/tcp | OpenSSH | 4.7p1 | 3.7 | LOW | high | NVD |
| CVE-2009-1888 | 139/445/tcp | Samba smbd | 3.X-4.X | 5.8 | MEDIUM | medium | NVD |
| CVE-2009-2906 | 139/445/tcp | Samba smbd | 3.X-4.X | 4.0 | MEDIUM | medium | NVD |
| CVE-2010-0926 | 139/445/tcp | Samba smbd | 3.X-4.X | 3.5 | LOW | medium | NVD |
| CVE-2005-3630 | 80/tcp | Apache httpd | 2.2.8 | 5.0 | MEDIUM | medium | NVD |
| CVE-2006-4625 | 80/tcp | Apache httpd/PHP | 2.2.8 | 3.6 | LOW | medium | NVD |
| CVE-2023-51764 | 25/tcp | Postfix smtpd | n/a | 5.3 | MEDIUM | medium | NVD |

**Source unique :** `data/cves.json` (généré le 2026-11-19T10:55:35Z), tracé vers `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml`.

### 5.2 Répartition par sévérité

| Sévérité | Nombre | CVE |
|----------|--------|-----|
| CRITICAL | 2 | CVE-2011-2523, CVE-2021-27171 |
| HIGH | 8 | CVE-2007-2446, CVE-2008-4314, CVE-2010-0728, CVE-1999-0236, CVE-2000-1195, CVE-2005-0337, CVE-2007-2444, CVE-2022-39028 |
| MEDIUM | 8 | CVE-2007-0452, CVE-2007-2447, CVE-2020-8797, CVE-2009-1888, CVE-2009-2906, CVE-2005-3630, CVE-2023-51764, CVE-2006-4625 (LOW en fait) |

*Correction : CVE-2006-4625 (3.6, LOW) et CVE-2008-5161 (3.7, LOW), CVE-2010-0926 (3.5, LOW) comptent pour 3 LOW.*

| Sévérité | Nombre |
|----------|--------|
| CRITICAL | 2 |
| HIGH | 8 |
| MEDIUM | 7 |
| LOW | 3 |
| **Total** | **20** |

### 5.3 Niveaux de confiance

- **high (2) :** CVE-2008-5161 (OpenSSH 4.7p1 exact), CVE-2011-2523 (vsftpd 2.3.4 exact).
- **medium (18) :** reste des CVE, correspondance produit/plage de versions ou bannière précise.

### 5.4 Services sans CVE correspondante (non corrélés)

Trois services n'ont fait l'objet d'aucune CVE dans `data/cves.json` :

| Port | Service | Produit | Motif |
|------|---------|---------|-------|
| 512/tcp | exec | netkit-rsh rexecd | aucun CVE NVD pour ce produit/version |
| 513/tcp | login | OpenBSD or Solaris rlogind | aucun CVE NVD pour ce produit/version |
| 514/tcp | shell | Netkit rshd | aucun CVE NVD pour ce produit/version |

Le port 111/tcp (rpcbind) a une CVE fausse positive documentée (CVE-2003-1070, cible Solaris) mais aucune CVE retenue.

### 5.5 Faux positifs documentés et exclus

Douze (12) CVE candidates ont été identifiées comme faux positifs probables et exclues du plan d'exploitation (détail dans `data/cves.json`, champ `false_positives`) :

CVE-2007-4752, CVE-2010-4755 (SSH, version/hors cible), CVE-2004-0925, CVE-2024-27305 (Postfix, cible macOS/aiosmtpd), CVE-1999-0071, CVE-2000-1206, CVE-2002-1850, CVE-2003-0249, CVE-2004-0493, CVE-2004-2343, CVE-2005-3352 (Apache, versions hors plage), CVE-2003-1070 (rpcbind, cible Solaris).

Aucune de ces CVE n'est citée dans le plan MITRE (`plans/attack-plan.json`).

### 5.6 CVE KEV / EPSS

Aucune des 20 CVE retenues n'est marquée dans le catalogue CISA KEV (`kev: false` pour toutes dans `data/cves.json`). Les données EPSS n'ont pas été consultées (non disponibles dans le périmètre de cette mission).

---

## 6. Plan d'attaque MITRE ATT&CK

Le plan d'attaque complet est défini dans `plans/attack-plan.json` (source de vérité) et restitué lisiblement dans `plans/attack-plan.md`. Il est cohérent avec les deux fichiers (validé par `scripts/mitre/validate_attack_plan.py`, revue R-008 PASS).

### 6.1 Synthèse par phase

| Phase | Tactic ATT&CK | ID tactic | Étapes | Services cibles | CVE associées |
|-------|---------------|-----------|--------|-----------------|---------------|
| P1 — Reconnaissance | Reconnaissance | TA0043 | S1.1 | 21, 22, 23, 25, 80, 111, 139, 445, 512, 513, 514/tcp | 20 CVE |
| P2 — Initial Access | Initial Access | TA0001 | S2.1, S2.2, S2.3, S2.4 | 80, 21, 139/445, 23/tcp | 10 CVE |
| P3 — Execution | Execution | TA0002 | S3.1 | 21, 139, 445/tcp | CVE-2011-2523, CVE-2007-2447 |
| P4 — Privilege Escalation | Privilege Escalation | TA0004 | S4.1 | 139, 445/tcp | CVE-2007-2444, CVE-2009-1888, CVE-2010-0728, CVE-2010-0926 |
| P5 — Credential Access | Credential Access | TA0006 | S5.1 | 22/tcp | CVE-2008-5161 |
| P6 — Lateral Movement | Lateral Movement | TA0008 | S6.1 | 22/tcp | CVE-2008-5161 |
| P7 — Collection | Collection | TA0009 | S7.1 | 25/tcp | CVE-2005-0337, CVE-2023-51764 |
| P8 — Impact | Impact | TA0040 | S8.1, S8.2 | 139/445, 23/tcp | CVE-2007-0452, CVE-2008-4314, CVE-2009-2906, CVE-2022-39028 |

**Total : 12 étapes, 8 techniques ATT&CK uniques (T1595.002, T1190, T1210, T1059, T1068, T1110, T1021.004, T1499), 20 CVE citées.**

### 6.2 Étapes à risque élevé ou critique (non exécutées)

Les étapes suivantes présentent un risque `high` ou `critical` et sont **conditionnées à un accord utilisateur explicite** (`requires_user_approval: true`) ; elles n'ont pas été exécutées :

- **S2.2 — vsftpd 2.3.4 (21/tcp), CVE-2011-2523, risque critical :** porte-arrière ouvrant un shell sur 6200/tcp. C'est l'étape d'accès initial la plus critique du lab.
- **S2.1 — Apache httpd 2.2.8 (80/tcp), risque high :** exploitation d'application publique exposée.
- **S2.3 — Samba (139/445/tcp), risque high :** exécution de code à distance via MS-RPC (CVE-2007-2446, CVE-2007-2447).
- **S2.4 — telnetd (23/tcp), risque high :** contournement d'authentification ou déni de service.
- **S3.1, S4.1, S8.1, S8.2 :** risque high, exécution, élévation de privilèges, déni de service.

### 6.3 Preuves attendues et traçabilité

Chaque étape du plan référence ses preuves attendues dans `plans/attack-plan.json` (champ `expected_evidence`), principalement :
- `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml`
- `data/services.json`
- `data/cves.json`

> Note mineure (R-008/F-001) : l'étape S2.1 du JSON référence par coquille `data/cves.gov` au lieu de `data/cves.json` dans une chaîne `expected_evidence`. Le Markdown et le validateur citent correctement `data/cves.json`. Cette coquille n'affecte pas les IDs, CVE ni techniques et est consignée comme non bloquante.

---

## 7. Preuves et traçabilité

### 7.1 Inventaire des preuves brutes (`evidence/raw/`)

| Fichier | Nature | Horodatage | Empreinte SHA-256 |
|---------|--------|------------|-------------------|
| `nmap-192.168.56.103-20261119T095751Z.xml` | Sortie XML nmap | 2026-11-19T09:57:51Z | `0371780a138ae77af0c28424cddf247b32fd10a8d4d6b895376cc2b02df4cd2a` |
| `nmap-192.168.56.103-20261119T095751Z.gnmap` | Sortie grepable nmap | 2026-11-19T09:57:51Z | `b774c88180238a7bd7f212644aac7fd98e70326d32b667593c7de1e14659c05e` |
| `nmap-192.168.56.103-20261119T095751Z.nmap` | Sortie texte nmap | 2026-11-19T09:57:51Z | `88fd49fc968850a2e6a5deb331f1fd473a8e4e8861e36d4b915f691d4eafe123` |
| `recon-192.168.56.103-20261119T095751Z.log` | Log de reconnaissance | 2026-11-19T09:57:51Z | non listée dans le manifeste (finding R-005/F-001) |
| `manifest-192.168.56.103-20261119T095751Z.sha256` | Manifeste SHA-256 | 2026-11-19T09:57:51Z | — |

Les empreintes sont issues de `evidence/raw/manifest-192.168.56.103-20261119T095751Z.sha256`. Les preuves brutes n'ont jamais été modifiées depuis leur création.

### 7.2 Livrables de données normalisées

| Fichier | Nature | Généré le | Source |
|---------|--------|-----------|--------|
| `data/services.json` | Inventaire des services (11) | 2026-11-19T09:58:03Z | `evidence/raw/nmap-...xml` |
| `data/cves.json` | Corrélation CVE (20) | 2026-11-19T10:55:35Z | `data/services.json`, preuve nmap |
| `plans/attack-plan.json` | Plan MITRE ATT&CK | 2026-11-19T12:08:33Z | `data/services.json`, `data/cves.json` |
| `plans/attack-plan.md` | Plan MITRE lisible | 2026-11-19T12:08:33Z | `plans/attack-plan.json` |

### 7.3 Rapports de revue indépendante

| Revue | Tâche | Verdict | Date | Rapport |
|-------|-------|---------|------|---------|
| R-001 | T02 | CHANGES_REQUIRED → résolu | 2026-11-19T12:00:00Z | `review/review-T02-20261119T120000Z.md` |
| R-002 | T02 | PASS | 2026-11-19T09:35:25Z | `review/review-T02-20261119T093525Z.md` |
| R-003 | T03 | CHANGES_REQUIRED → résolu | 2026-11-19T09:46:54Z | `review/review-T03-20261119T094654Z.md` |
| R-004 | T03 | PASS | 2026-11-19T09:52:50Z | `review/review-T03-20261119T095250Z.md` |
| R-005 | T06 | PASS | 2026-11-19T10:10:50Z | `review/review-T06-20261119T101050Z.md` |
| R-006 | T07 | CHANGES_REQUIRED → résolu | 2026-11-19T10:39:32Z | `review/review-T08-20261119T103932Z.md` |
| R-007 | T07 | PASS | 2026-11-19T11:00:03Z | `review/review-T08-20261119T110003Z.md` |
| R-008 | T09/T10 | PASS | 2026-11-19T12:18:05Z | `review/review-T10-20261119T121805Z.md` |

Toutes les revues aboutissent à un verdict `PASS` après traitement des findings.

---

## 8. Remédiation

Recommandations priorisées par risque, applicables à la VM Metasploitable2 (lab uniquement) :

1. **Critique — vsftpd 2.3.4 (21/tcp, CVE-2011-2523) :** désactiver ou supprimer le service FTP ; si indispensable, remplacer par une version moderne et supportée de vsftpd. La porte-arrière de la version 2.3.4 permet un accès shell distant non authentifié.
2. **Critique — telnetd (23/tcp, CVE-2021-27171, CVE-2022-39028, CVE-2000-1195) :** désactiver Telnet, protocole non chiffré et vulnérable ; privilégier SSH à jour.
3. **Élevé — Samba (139/445/tcp, CVE-2007-2446/2447, CVE-2008-4314, CVE-2010-0728, etc.) :** mettre à jour Samba au-delà de la version 3.0.25rc3 ; restreindre l'accès aux partages SMB ; désactiver `username map script` et les options MS-RPC non nécessaires.
4. **Élevé — Apache httpd 2.2.8 (80/tcp) :** mettre à jour le serveur web ; supprimer les scripts CGI inutiles ; appliquer `mod_security` ou équivalent.
5. **Moyen — OpenSSH 4.7p1 (22/tcp, CVE-2008-5161) :** mettre à jour OpenSSH ; désactiver les chiffreurs CBC en bloc si une mise à jour n'est pas possible immédiatement.
6. **Moyen — Postfix smtpd (25/tcp, CVE-2005-0337, CVE-2023-51764) :** configurer `smtpd_data_restrictions=reject_unauth_pipelining` et `smtpd_discard_ehlo_keywords=chunking` ; activer `smtpd_forbid_bare_newline=yes`.
7. **Services non corrélés (512/513/514/tcp) :** désactiver rsh/rlogin/rexec (protocoles non chiffrés, obsolètes).

---

## 9. Limites et risques résiduels

- **Portée de la reconnaissance :** scan limité aux ports TCP 1-1024, un seul hôte (`192.168.56.103`), un seul instantané (2026-11-19). Les services sur des ports >1024 ou les changements de configuration ultérieurs ne sont pas couverts.
- **Versions déclarées par les bannières :** les versions de services proviennent des bannières nmap (`-sV`) et peuvent être inexactes ou modifiées par l'administrateur de la cible.
- **CVE à confiance medium :** la majorité des CVE (18/20) ont un niveau de confiance `medium` (correspondance produit/plage de versions, non version exacte). Certaines CVE sur telnetd (CVE-2020-8797 Juplink, CVE-2021-27171 FiberHome, CVE-2022-39028 GNU Inetutils) concernent des produits spécifiques qui peuvent ne pas correspondre exactement à Metasploitable2 ; à confirmer avant toute exploitation.
- **Faux positifs exclus :** 12 CVE candidates ont été exclues comme faux positifs probables ; une réévaluation peut être nécessaire si le contexte change.
- **Plan préparatoire uniquement :** le plan MITRE est documentaire. Aucune étape d'exploitation n'a été exécutée ; l'évaluation réelle des vulnérabilités nécessiterait des tests contrôlés avec accord utilisateur explicite.
- **Version ATT&CK déclarée :** la matrice ATT&CK v20.1 est déclarée vérifiée sur `attack.mitre.org` dans les fichiers de plan, mais n'a pas été re-vérifiée indépendamment par le reviewer (R-008).
- **Preuves brutes :** le manifeste SHA-256 omet le fichier de log de reconnaissance (finding R-005/F-001, non bloquant).
- **Données KEV/EPSS :** aucune donnée CISA KEV positive (toutes `kev: false`), EPSS non consulté.
- **Aucun test e2e :** le dossier `tests/e2e/` est vide ; aucun test de bout en bout contre la VM n'a été exécuté (lab non disponible pour cette tâche).

---

## 10. Conformité et sécurité

- **Aucun secret, identifiant ou token** n'apparaît dans ce rapport ni dans les preuves associées. Les identifiants de laboratoire restent dans `.env` (fichier ignoré par Git, jamais commité).
- **Aucune IP publique** n'est citée comme cible. L'unique adresse IP mentionnée (`192.168.56.103`) appartient au réseau lab RFC1918.
- **Aucune action intrusive** n'a été lancée sur la cible dans le cadre de cette tâche T11 (ni dans aucune tâche précédente : reconnaissance en lecture seule, corrélation CVE et plan documentaire uniquement).
- **Preuves brutes immuables :** aucun fichier de `evidence/raw/` n'a été modifié.
- **Répertoire `review/`** n'a pas été modifié par cette tâche (réservé au reviewer).

---

## 11. Annexes

### 11.1 Chaîne de génération du rapport (reproductibilité)

```bash
# 1. Activer l'environnement virtuel
source /home/yug/Documents/agentic/.venv/bin/activate

# 2. Générer le PDF depuis la source Markdown
python3 scripts/report/generate_report.py \
  --source reports/rapport-final.md \
  --output reports/rapport-final.pdf

# 3. Vérifier le PDF
ls -la reports/rapport-final.pdf
pdfinfo reports/rapport-final.pdf
pdftotext reports/rapport-final.pdf - | head -20
```

**Outils utilisés :** Python 3.12.3, weasyprint 70.0, pdftotext (poppler), pdfinfo.  
**Dépendances déclarées :** `requirements.txt` (weasyprint==70.0, jsonschema==4.23.0, pytest==8.3.3, requests==2.32.3, ruff==0.9.2).  
**pandoc :** absent, non requis (weasyprint utilisé directement via conversion Markdown→HTML intégrée au script).

### 11.2 Commandes de test

```bash
# Tests unitaires (pas de réseau, pas de cible lab)
source .venv/bin/activate && python3 -m pytest -m "not integration and not e2e"

# Validation du rapport généré
python3 -c "import json; d=json.load(open('tracking.json'))"  # JSON valide
ls -la reports/rapport-final.pdf                             # fichier existe, non vide
pdftotext reports/rapport-final.pdf - | head -20             # contenu lisible
```

### 11.3 Références

- `tracking.json` — état de mission et cible confirmée (192.168.56.103, 192.168.56.0/24).
- `evidence/raw/nmap-192.168.56.103-20261119T095751Z.xml` — preuve brute de reconnaissance (nmap 7.94SVN).
- `evidence/raw/manifest-192.168.56.103-20261119T095751Z.sha256` — empreintes SHA-256 des preuves.
- `data/services.json` — inventaire normalisé des 11 services (T05).
- `data/cves.json` — corrélation des 20 CVE avec source et confiance (T07/T08).
- `plans/attack-plan.json` — plan MITRE ATT&CK structuré (T09).
- `plans/attack-plan.md` — plan MITRE lisible (T09).
- `review/` — 8 rapports de revue indépendante, verdicts PASS (R-001 à R-008).
- https://attack.mitre.org/ — MITRE ATT&CK (version v20.1 déclarée).
- https://nvd.nist.gov/ — National Vulnerability Database (source des CVE).
- `configs/lab-access.md` — accès et périmètre du laboratoire.

---

*Fin du rapport. Généré le 2026-11-19. Ce document est la source de vérité ; le PDF associé (`reports/rapport-final.pdf`) en est le rendu généré par weasyprint 70.0.*
