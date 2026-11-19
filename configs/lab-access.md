# Accès au laboratoire — projet agentique

## Objet et date

Ce document décrit l'accès au laboratoire local mis à disposition des agents du
projet `/home/yug/Documents/agentic`. Date de transfert : 2026-11-17.

Les identifiants du laboratoire sont dans `/home/yug/Documents/agentic/.env`.
Aucun mot de passe n'apparaît dans ce document.

## Périmètre

- Réseau local uniquement : `192.168.56.0/24`.
- Aucune cible publique, aucun système de production, aucun accès Internet.
- **Host-only** — réseau virtuel privé entre l'hôte et les VMs, sans route vers
  l'extérieur.
- Hyperviseur : VirtualBox 7.1.18 sur l'hôte Linux `yug`.

## Machines virtuelles

| Nom | UUID | Rôle | IP | Utilisateur | Mot de passe | Snapshot courant |
|---|---|---|---|---|---|---|
| `Kali` | `6027232a-f968-4310-b5fe-f803a8f0f489` | Attaquant : outils offensifs | `192.168.56.101` | `kali` | `KALI_PASS` dans `.env` | `pre-phase0-2026-11-16` |
| `Metasploitable2` | `20fed79a-4e51-4fd0-8c8c-c2f3a3c5da97` | Cible Linux vulnérable | `192.168.56.103` | `msfadmin` | `METASPLOITABLE_PASS` dans `.env` | `pre-phase0-2026-11-16` |

**Snapshot** — copie figée de l'état d'une VM, utilisée pour revenir à un état
propre. Aucun snapshot n'a été restauré pendant le transfert.

## Réseau

- Interface : `vboxnet0`.
- Adresse de l'hôte : `192.168.56.1/24`.
- **DHCP** — protocole d'attribution automatique d'adresses IP ; désactivé sur
  `vboxnet0`.
- Chaque VM utilise une adresse IP statique sur le seul adaptateur `vboxnet0`.
- Aucun mode pont, aucune redirection NAT, aucune route vers Internet.

## Commandes d'accès

Chargez les variables depuis `.env` avant toute commande :

```bash
set -a
. /home/yug/Documents/agentic/.env
set +a
```

### Démarrer et arrêter les VMs

```bash
VBoxManage startvm "Kali" --type headless
VBoxManage startvm "Metasploitable2" --type headless
VBoxManage list runningvms
VBoxManage controlvm "Kali" acpipowerbutton
VBoxManage controlvm "Metasploitable2" acpipowerbutton
```

**Headless** — démarrage sans fenêtre de console locale sur l'hôte.
`acpipowerbutton` demande un arrêt propre au système invité.

### SSH vers Kali

```bash
sshpass -p "$KALI_PASS" ssh $SSH_OPTS "$KALI_USER@$KALI_IP" 'id; hostname'
```

**SSH** — protocole d'accès distant chiffré. **sshpass** — outil qui fournit le
mot de passe à SSH sans saisie interactive.

### SSH vers Metasploitable 2

OpenSSH récent refuse la clé d'hôte héritée `ssh-rsa`. Ajoutez les deux options :

```bash
sshpass -p "$METASPLOITABLE_PASS" ssh $SSH_OPTS \
  -o HostKeyAlgorithms=+ssh-rsa \
  -o PubkeyAcceptedAlgorithms=+ssh-rsa \
  "$METASPLOITABLE_USER@$METASPLOITABLE_IP" 'id; hostname'
```

Sans ces options, la connexion échoue avec :
`no matching host key type found. Their offer: ssh-rsa,ssh-dss`.

### Copier un fichier

```bash
sshpass -p "$KALI_PASS" scp $SSH_OPTS ./fichier-local "$KALI_USER@$KALI_IP:/tmp/"
sshpass -p "$METASPLOITABLE_PASS" scp $SSH_OPTS \
  -o HostKeyAlgorithms=+ssh-rsa \
  -o PubkeyAcceptedAlgorithms=+ssh-rsa \
  ./fichier-local "$METASPLOITABLE_USER@$METASPLOITABLE_IP:/tmp/"
```

**SCP** — copie de fichiers au-dessus de SSH. Laissez `$SSH_OPTS` sans
guillemets : le shell doit séparer chaque option.

### Vérifier les ports

```bash
nc -zv -w 5 "$KALI_IP" 22
nc -zv -w 5 "$METASPLOITABLE_IP" 21
nc -zv -w 5 "$METASPLOITABLE_IP" 22
nc -zv -w 5 "$METASPLOITABLE_IP" 80
```

**nc** — client réseau minimal. `-z` teste l'ouverture du port sans envoyer de
données, `-w 5` limite l'attente à cinq secondes.

## Lien avec le projet cours

- Racine : `/home/yug/Documents/hacking-contre-mesure-niveau-2`.
- `AGENTS.md` : rôles et règles de travail des agents du cours.
- `.opencode/agent/orchestrator.md`, `.opencode/agent/hacker.md`,
  `.opencode/agent/student.md`, `.opencode/agent/sysadmin.md` : définitions des
  agents du cours.
- `tracking.db` : suivi d'avancement, en lecture seule pour les agents du projet
  agentique.
- `chapitre-01.md` à `chapitre-05.md` : supports de cours et labs.
- Preuves brutes : fichiers référencés depuis les chapitres sous `preuves/...`.

## Règles de collaboration

- Les agents du projet agentique peuvent lire le projet cours.
- Ils ne doivent pas écrire `tracking.db`.
- Ils ne doivent pas modifier les preuves brutes.
- Ils ne doivent jamais committer de secret.
- Les identifiants du laboratoire restent dans `.env`, ignoré par Git.
- Le `.env` du projet cours contient d'autres secrets, notamment un jeton GitHub
  et des identités Git : ne pas le copier.

## État constaté au transfert

- `vboxnet0` : recréé, `192.168.56.1/24`, DHCP désactivé.
- VMs : `Kali` et `Metasploitable2` démarrées en mode headless.
- Ping : `192.168.56.101` et `192.168.56.103` répondent.
- Ports joignables : `22` sur Kali ; `21`, `22` et `80` sur Metasploitable 2.
- SSH Kali : authentification validée avec l'utilisateur `kali`.
- SSH Metasploitable 2 : authentification validée avec l'utilisateur `msfadmin`,
  après ajout des options d'algorithme hérité.
- Limite : la validation SSH automatique dépend de `sshpass` sur l'hôte. Sans
  `sshpass`, validez l'ouverture du port 22 et faites l'authentification en
  interactif.
