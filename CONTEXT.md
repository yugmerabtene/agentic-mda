# Contexte de mission — Lab Metasploitable

## Objectif

Reprendre le cours, les fichiers de preuve existants et le contenu déjà présent dans le
dépôt, puis produire une mission complète de laboratoire local :

1. un script automatisé et paramétrable de reconnaissance de la VM Metasploitable ;
2. une corrélation des services et versions découverts avec des CVE vérifiables ;
3. un plan d'attaque MITRE ATT&CK complet, en JSON et en Markdown ;
4. une documentation finale en PDF (avec sa source Markdown) reproductible.

## Cible et périmètre

- Cible : VM Metasploitable sur hyperviseur local.
- Adresse : à confirmer par l'utilisateur et à consigner dans `tracking.json`.
- Réseau : privé RFC1918 ou loopback uniquement.
- Aucune action hors du lab, aucune cible publique, aucune action destructive sans
  confirmation explicite.

## Entrées à réutiliser

- Le cours et les supports déjà disponibles.
- Les fichiers de preuve éventuellement présents dans `evidence/`.
- Le contenu actuel du dépôt (`scripts/`, `data/`, `plans/`, `reports/`, `review/`).
- L'état d'avancement dans `tracking.json`.

## Livrables attendus

- `scripts/recon/` : script de reconnaissance paramétrable et testé.
- `data/services.json` : inventaire normalisé des services.
- `data/cves.json` : corrélation CVE avec source et niveau de confiance.
- `plans/attack-plan.json` : plan MITRE ATT&CK structuré.
- `plans/attack-plan.md` : plan MITRE lisible et cohérent avec le JSON.
- `reports/rapport-final.md` : rapport source.
- `reports/rapport-final.pdf` : rapport final généré depuis la source.
- `review/` : rapports de revue indépendante.

## Contraintes

- Tout livrable technique passe par une revue indépendante avec verdict `PASS`.
- Les identifiants CVE et MITRE sont vérifiés auprès de sources autoritatives.
- Les preuves brutes sont horodatées et ne sont jamais modifiées.
- Les secrets restent hors des rapports et des preuves.
- Les scripts n'embarquent aucune IP codée en dur.

## À confirmer par l'utilisateur

- Adresse IP de la VM cible et réseau du lab.
- Moyens d'accès à l'hyperviseur, si nécessaire.
- Périmètre exact des actions autorisées (reconnaissance seule ou exploitation contrôlée).
