# Vague 2 — Hygiène de dépôt

## Avant de commencer

```
git status
git pull origin main
```

Vérifie qu'il n'y a pas de divergence avant de toucher à quoi que ce soit. Le push de la Vague 1 vient d'être fait, donc `origin/main` doit correspondre à l'état local — signale-moi si ce n'est pas le cas plutôt que de continuer.

## Contexte

Cette vague ne touche à AUCUNE logique métier — uniquement au tracking git, à la suppression de fichiers morts/dupliqués, et à la synchronisation de `requirements.txt` avec les imports réels. Rien ici ne doit changer le comportement du pipeline, des scrapers, de l'API ou des dashboards.

## Corrections attendues

### 1. `.gitignore` — combler les trous constatés dans l'audit

Ajoute au minimum :
```
data/*.db
data/raw_*.json
logs/
*.log
audit.json
vulnerability_assessment_*.json
.venv/
__pycache__/
*.pyc
```

Vérifie s'il existe déjà des entrées partielles ou redondantes avant d'ajouter (ne duplique pas). Une fois le `.gitignore` mis à jour, ces fichiers resteront trackés s'ils l'étaient déjà avant — c'est normal, `.gitignore` n'agit que sur les nouveaux fichiers. Traite ce retrait du tracking dans le point suivant.

### 2. Retirer du tracking git les fichiers qui n'auraient jamais dû l'être

```
git rm --cached data/threats.db
git rm --cached data/raw_*.json
git rm --cached logs/orchestrator_metrics.json
git rm --cached logs/orchestrator.log
git rm --cached audit.json
git rm --cached vulnerability_assessment_*.json
```
(adapte les chemins exacts à ce qui existe réellement — utilise `git ls-files` pour lister ce qui est effectivement tracké avant de lancer les commandes, ne devine pas les noms).

Important : `git rm --cached` supprime le fichier du suivi git mais **le garde sur le disque local** — ne pas utiliser `git rm` seul, qui supprimerait aussi le fichier physique dont j'ai besoin pour continuer à travailler dessus localement.

### 3. Supprimer le code mort

- `core/classifier_old.py` — confirmé non importé nulle part dans l'audit. Vérifie une dernière fois avec un `grep -r "classifier_old"` sur tout le dépôt avant de supprimer, pour être sûr à 100%.
- `testing/agent_tester.py` — l'audit note qu'il n'est utilisé que par `testing/cli.py`, en doublon quasi-identique de `agent_scanner.py` qui lui est câblé au dashboard. **Ne supprime pas celui-ci** sans me demander d'abord — contrairement à `classifier_old.py`, celui-ci est encore utilisé quelque part (`cli.py`), donc le supprimer casserait la CLI. Signale-le-moi juste, on décidera en Vague 3 s'il faut fusionner les deux classes plutôt que d'en supprimer une à l'aveugle.

### 4. Scripts de debug à la racine

`debug_other_threats.py`, `fix_keyword_matching.py`, `final_reclassify.py` : déplace-les dans un nouveau dossier `scripts/maintenance/` plutôt que de les supprimer — ils ont modifié la base de prod par le passé donc ils ont une valeur documentaire/historique, mais n'ont rien à faire à la racine d'un dépôt qui se veut "production ready". Ajoute une ligne en tête de chacun précisant qu'il s'agit d'un script ponctuel de maintenance manuelle, pas d'un composant du pipeline.

### 5. `requirements.txt` — synchroniser avec les imports réels

- Ajoute : `python-dotenv` (utilisé dans `censys_scraper.py`), `pytest`, `pytest-cov`
- Concernant `schedule` vs `APScheduler` : garde `schedule` dans `requirements.txt` (c'est ce qui est réellement importé et utilisé dans `orchestrator.py`) — la doc a déjà été corrigée en Vague 1 pour dire `schedule`, donc les deux doivent maintenant être cohérents.
- Vérifie si `pydantic` et `beautifulsoup4` sont vraiment inutilisés comme le signale l'audit (`grep -r "import pydantic"`, `grep -r "beautifulsoup\|bs4"`). Si confirmé inutilisés, retire-les de `requirements.txt` — sauf si tu sais qu'on va s'en servir dès la Vague 3 (le point Pydantic sur l'endpoint API), auquel cas garde `pydantic` et dis-le-moi.

### 6. Fichiers de résultats de scan ponctuels

Les fichiers type `mistral_audit_FINAL_REAL.json` et autres résultats de scan à la racine (mentionnés dans les sessions précédentes) : vérifie s'ils sont trackés en git. S'ils datent d'une session de test ponctuelle et ne sont pas régénérés par un script actuel, propose-moi d'en faire soit un dossier `results/archive/` avec une note explicative, soit un retrait du tracking (comme le point 2) — je trancherai selon ce que tu trouves, ne décide pas seul pour ceux-là spécifiquement car ce sont mes données de résultats empiriques du rapport de thèse.

## Contrainte de méthode

- Aucune modification de fichier `.py` en dehors de : suppression de `classifier_old.py`, déplacement (pas modification de contenu) des 3 scripts de debug, et l'ajout de la ligne d'en-tête mentionnée au point 4.
- Ne touche pas à `testing/agent_tester.py` — juste un signalement.
- Pour le point 6, propose-moi les options trouvées, n'exécute rien tant que je n'ai pas choisi.
- Une fois terminé : `git status` complet + résumé de ce qui a été fait, avant tout commit.