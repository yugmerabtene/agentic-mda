---
name: recon
description: "Méthodologie de reconnaissance contrôlée d'une VM Metasploitable : nmap, énumération de services, preuves brutes, normalisation et corrélation CVE. À charger pour les tâches de découverte, scan, énumération ou mapping service/version vers CVE."
---

# Reconnaissance et corrélation CVE

## Préconditions

- Cible confirmée par l'utilisateur et consignée dans `tracking.json`.
- Adresse dans un réseau privé RFC1918 ou loopback. Refuser toute IP publique.
- Vérifier l'identité de la cible avant le scan complet (bannière, MAC sur le réseau
  local, nom d'hôte) pour éviter de scanner un autre actif.
- Les scripts et commandes doivent accepter `--target` sans IP codée en dur.

## Chaîne de scan recommandée

Toujours privilégier les options non destructrices et conserver chaque sortie brute.

```bash
# 1. Découverte locale (adapter l'interface et le réseau)
nmap -sn 192.168.56.0/24 -oA evidence/raw/discovery-<timestamp>

# 2. Ports TCP ouverts (fallback -sT si pas de privilèges root)
nmap -Pn -sS -p- --min-rate 1000 --max-retries 2 \
  -oA evidence/raw/tcp-full-<target>-<timestamp> <target>

# 3. Détection de versions et scripts par défaut raisonnables
nmap -Pn -sV -sC --version-all -p <ports_ouverts> \
  -oA evidence/raw/service-<target>-<timestamp> <target>

# 4. UDP limité aux ports courants
nmap -Pn -sU --top-ports 100 --max-retries 1 \
  -oA evidence/raw/udp-<target>-<timestamp> <target>
```

- `--script vuln` ou les scripts d'exploitation sont intrusifs : demander l'accord de
  l'utilisateur avant exécution.
- Limiter la charge : `--min-rate` / `--max-rate`, `--max-retries`, timeouts.
- Ne pas lancer de scan de toute la plage si seule l'IP cible est autorisée.

## Énumération par service

Après le scan de versions, cibler les services réellement présents. Exemples de contrôles
non destructifs sur une Metasploitable :

- FTP : bannière, accès anonyme éventuel.
- SSH : bannière, méthodes d'authentification.
- Telnet : bannière.
- SMTP : bannière, commandes `HELO`/`VRFY` selon autorisation.
- DNS : version si exposée.
- HTTP/Tomcat : en-têtes, pages par défaut, répertoires listés (`http-enum`).
- SMB : `smb-enum-shares`, `smb-os-discovery`, `enum4linux-ng` (lecture seule).
- MySQL/PostgreSQL : bannière et version, sans tentative d'authentification.
- VNC : bannière, absence d'authentification constatée passivement.
- rpcbind/NFS : exports visibles.
- IRC/distcc : bannière et version.

Ne pas utiliser d'identifiants par défaut ni d'exploit dans la phase de reconnaissance
sans autorisation explicite.

## Preuves

Pour chaque exécution :

- sortie brute nmap `.nmap`, `.xml`, `.gnmap` dans `evidence/raw/` ;
- log de commande avec horodatage UTC et code de sortie ;
- manifeste SHA-256 des preuves ;
- aucune modification ultérieure des fichiers bruts.

## Normalisation `data/services.json`

```json
{
  "schema_version": "1.0",
  "generated_at": "YYYY-MM-DDTHH:MM:SSZ",
  "target": { "ip": "192.168.56.10", "hostname": "metasploitable", "os": "Linux" },
  "services": [
    {
      "port": 21,
      "protocol": "tcp",
      "state": "open",
      "service": "ftp",
      "product": "vsftpd",
      "version": "2.3.4",
      "cpe": ["cpe:/a:vsftpd:vsftpd:2.3.4"],
      "extra_info": {},
      "source": "evidence/raw/service-<target>-<timestamp>.xml"
    }
  ],
  "unmatched": []
}
```

Champs obligatoires : port, protocole, état, service, source. Ne pas déduire une version
absente de la bannière.

## Corrélation CVE

1. Construire les candidats depuis les CPE et les versions exactes.
2. Interroger les sources :
   - `searchsploit --json <produit> <version>` (local, hors ligne) ;
   - API NVD 2.0 (`cpeName`, `keywordSearch`) avec cache et respect des quotas ;
   - CISA KEV et EPSS si disponibles pour la priorisation.
3. Vérifier chaque identifiant CVE auprès de la source ; ne jamais inventer.
4. Évaluer la confiance :
   - `high` : CPE/version exacte confirmée ;
   - `medium` : plage de versions ou bannière fiable ;
   - `low` : correspondance approximative à confirmer manuellement.
5. Dédupliquer par CVE et fusionner les services concernés.
6. Signaler les faux positifs probables et les services sans CVE.

Sortie `data/cves.json` :

```json
{
  "schema_version": "1.0",
  "generated_at": "YYYY-MM-DDTHH:MM:SSZ",
  "target": "192.168.56.10",
  "cves": [
    {
      "id": "CVE-YYYY-NNNN",
      "source": "nvd|searchsploit",
      "source_url": "https://...",
      "cvss": 9.8,
      "severity": "critical",
      "confidence": "high",
      "services": ["21/tcp"],
      "matched_on": { "cpe": "cpe:/a:...", "version": "..." },
      "description": "...",
      "references": ["https://..."],
      "kev": false
    }
  ],
  "unmatched_services": []
}
```

## Critères d'acceptation du script de reconnaissance

- CLI : `--target`, `--profile`, `--output`, `--dry-run`, `--timeout`, `--rate`.
- Refus explicite d'une cible hors RFC1918/loopback.
- Sorties brutes et normalisées générées avec horodatage.
- Journalisation et codes de sortie cohérents.
- Tests unitaires avec réseau mocké ; tests d'intégration marqués.
- Documentation des commandes et des prérequis (root, nmap, searchsploit).
- Aucune tentative d'exploitation.
