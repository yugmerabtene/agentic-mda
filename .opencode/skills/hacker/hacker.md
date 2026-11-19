# Skill: hacker

# Exploitation contrôlée — Lab Metasploitable

## Objet

Guider l'exécution contrôlée du plan d'attaque MITRE ATT&CK (`plans/attack-plan.md`) depuis la machine attaquante Kali (`192.168.56.101`) vers la cible Metasploitable (`192.168.56.103`), en s'appuyant sur les données de reconnaissance (`data/services.json`) et de corrélation CVE (`data/cves.json`).

Ce skill documente la méthodologie d'exploitation et la conservation des preuves des exploits réussis. Il ne contient **aucun exploit réel, aucun code malveillant, aucun secret**.

## Cible et périmètre

- **Cible unique** : `192.168.56.103` (Metasploitable2, RFC1918, confirmé dans `tracking.json`).
- **Machine attaquante** : `192.168.56.101` (Kali, `192.168.56.0/24`).
- Toute autre IP est refusée. Aucune action hors du lab.

## Règles de sécurité (obligatoires, non contournables)

- **Confirmation explicite** : chaque action intrusive (exploit, brute force, modification de service, persistance, exfiltration) nécessite une confirmation utilisateur explicite, même en lab.
- **Dry-run obligatoire** : toute action doit d'abord être validée en mode `--dry-run` sans impact sur la cible.
- **Journalisation** : toutes les actions sont horodatées (ISO 8601 UTC) et consignées dans `evidence/raw/`.
- **Preuves des exploits réussis** : chaque exploit qui aboutit doit faire l'objet d'une preuve brute horodatée dans `evidence/raw/` (ex. : capture de shell, sortie de commande, dump de fichier, preuve d'élévation de privilèges). Ces preuves ne sont jamais modifiées après création.
- **Aucun secret** : identifiants et tokens restent dans `.env`, jamais dans les rapports ni les preuves.
- **Aucun exploit inventé** : seules les CVE vérifiées dans `data/cves.json` peuvent être référencées.
- **Aucune IP codée en dur** dans les scripts.

## Méthodologie

### 1. Validation du périmètre
Confirmer que la cible est `192.168.56.103` (RFC1918) et qu'elle figure dans `tracking.json`.

### 2. Relecture de l'attaque-plan
Vérifier que chaque technique MITRE est liée à des CVE présentes dans `data/cves.json` et que les préconditions sont documentées dans `plans/attack-plan.md`.

### 3. Dry-run
Simuler l'action sans impact sur la cible. Vérifier que la commande est plausible et que le périmètre est respecté.

### 4. Confirmation utilisateur
Demander l'accord explicite avant toute action intrusive. Consigner la décision dans `tracking.json` (décision D-xxx).

### 5. Exécution contrôlée
Lancer l'action, capturer les preuves brutes, les horodater (ISO 8601 UTC).

### 6. Documentation des preuves
- Stocker les preuves brutes dans `evidence/raw/` (noms de fichiers en `kebab-case`, horodatage UTC).
- Créer un manifeste SHA-256 des preuves si plusieurs fichiers.
- Ne jamais modifier une preuve brute après création.
- Consigner le lien entre chaque preuve et l'étape de l'attaque-plan correspondante.

## Livrables attendus

- Preuves brutes horodatées dans `evidence/raw/` (y compris preuves des exploits réussis).
- Journal d'exécution dans `evidence/raw/`.
- Mise à jour de `tracking.json` (statut, artefacts, verdict, horodatage).
- Décisions d'exploitation consignées dans `decisions` de `tracking.json`.

## Structure des preuves d'exploitation

Pour chaque exploit tenté :

```
evidence/raw/exploit-<cve>-<port>-<timestamp>Z.out      # sortie brute de l'exploit
evidence/raw/exploit-<cve>-<port>-<timestamp>Z.log      # journal d'exécution
evidence/raw/manifest-<timestamp>Z.sha256               # empreintes SHA-256
```

## Interdictions

- Aucune action sur une IP publique ou hors `192.168.56.0/24`.
- Aucun exploit, brute force, persistance ou exfiltration sans confirmation explicite utilisateur.
- Aucun secret dans les livrables ou les preuves.
- Aucune modification des preuves brutes existantes.
- Aucun CVE ou identifiant MITRE inventé.

## Références

- `plans/attack-plan.md` : plan d'attaque MITRE ATT&CK.
- `data/cves.json` : corrélation CVE avec source et niveau de confiance.
- `data/services.json` : inventaire normalisé des services.
- `evidence/raw/` : preuves brutes (reconnaissance et exploitation).
- `tracking.json` : état d'avancement et décisions.
