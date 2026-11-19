# VIGIE — site de veille cybersécurité

Site de veille SSI statique, alimenté automatiquement par des flux publics et enrichi de fiches d'analyse rédigées à la main.
Thèmes suivis : sécurité de l'IA, santé, vulnérabilités exploitées, rançongiciels, fuites de données, réglementation (AI Act, NIS 2), identité, chaîne d'approvisionnement, menaces étatiques.

Aucune dépendance : HTML, CSS et JavaScript côté page ; Python standard pour la collecte.

## Ce que fait le site

| Vue | Contenu |
|---|---|
| Tableau de bord | Chiffres clés, entrées critiques ou exploitées de la semaine, activité par thème sur 14 jours, dernières fiches, prochaine échéance |
| Flux | Toutes les entrées des 30 derniers jours, filtrables par thème, criticité, période, type et fiabilité de la source, avec recherche |
| Fiches | Fiches d'analyse en Markdown (`fiches/`) |
| Hebdo | Synthèse automatique de chaque semaine (volume par thème, entrées les plus sévères) sur 12 semaines |
| Agenda | Échéances réglementaires (`config/agenda.json`) |
| Méthode | Cycle de veille, grilles de fiabilité et de criticité, état de chaque source à la dernière collecte |

Le site publie aussi son propre flux RSS (`feed.xml`) : fiches et entrées critiques ou exploitées.

## Pipeline

```
GitHub Actions (toutes les 6 h, ou à la main, ou à chaque modification de config/, fiches/, scripts/)
  └─ python scripts/build.py
       ├─ flux RSS/Atom de config/sources.json   (filtrage optionnel par mots-clés)
       ├─ CISA KEV : vulnérabilités exploitées ajoutées sur 30 jours
       ├─ NVD : CVE critiques publiées sur 7 jours
       ├─ criticité : score CVSS si présent, sinon mots-clés (zero-day, exploitation active, RCE…)
       ├─ thèmes : règles de config/themes.json
       ├─ archive : data/archive.json (120 jours), la veille garde sa mémoire
       ├─ fiches : fiches/*.md → HTML
       └─ écrit data/veille.js, data/fiches.js, feed.xml, puis commit
```

Une source en panne n'interrompt jamais la construction : son état apparaît dans la vue Méthode.

## Publier sur GitHub Pages

1. Créer un dépôt public et y pousser ce dossier.
2. **Settings → Actions → General → Workflow permissions** : *Read and write permissions* (le workflow commite les données).
3. **Settings → Pages** : *Deploy from a branch*, branche `main`, dossier `/ (root)`.
4. Renseigner `repo` et `site_url` dans `config/site.json`.
5. Lancer le workflow une première fois : onglet **Actions → Veille — collecte des flux → Run workflow**.

## Travailler en local

```bash
python3 scripts/build.py              # collecte complète
python3 scripts/build.py --offline    # reconstruit depuis l'archive, sans réseau
python3 scripts/build.py --drafts     # inclut les fiches en brouillon (aperçu local uniquement)
python3 -m http.server 8765           # puis http://localhost:8765
```

Ne pas commiter une construction faite avec `--drafts` : les brouillons seraient publiés.

## Ajouter du contenu

- **Une source** : une entrée dans `config/sources.json` (`name`, `url`, `kind`, `cote`, `group`, et `require` pour ne garder que les articles pertinents).
- **Un thème** : une entrée dans `config/themes.json` (`pattern` insensible à la casse, `pattern_cs` pour les acronymes).
- **Une fiche** : copier `fiches/_modele.md` en `fiches/AAAA-MM-JJ-sujet.md`, rédiger, passer `draft: false`.
- **Une page** : copier `pages/_modele.md` en `pages/mon-slug.md` ; elle est servie à `#/p/mon-slug`. Avec `nav: true`, elle apparaît dans le menu (classée par `order`). Liens internes : `[texte](#/p/autre-page)`, `[texte](#/flux?theme=ia)`.
- Dans les fiches et les pages, les commentaires `<!-- … -->` ne sont jamais publiés : pratique pour des notes de rédaction.
- **Une échéance** : une entrée dans `config/agenda.json`, avec sa source et sa date de vérification.

## Règle de publication

Ce dépôt est public. Les fiches restent **génériques** : aucune information sur un établissement, un réseau interne, une adresse, un nom de machine ou une personne. L'analyse propre à un contexte interne se fait hors de ce dépôt.

## Crédits

Les entrées du flux renvoient à leurs sources ; titres et extraits restent la propriété de leurs auteurs.
