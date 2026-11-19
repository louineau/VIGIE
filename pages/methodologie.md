---
title: Méthodologie de la veille
nav: false
nav_label: Méthodologie
order: 20
summary: Comment l'information est collectée, qualifiée, analysée puis diffusée sur ce site.
updated: 2026-11-19
---

L'état des sources à la dernière collecte et les grilles de cotation sont aussi visibles dans la vue [Méthode](#/methode).

## Le cycle de veille

1. **Orientation** : définir les besoins à partir de la [problématique](#/p/problematique) et de ses cinq axes.
2. **Collecte** : flux RSS et Atom, catalogue CISA KEV, CVE critiques de la NVD, alertes par mots-clés.
3. **Tri et qualification** : attribution automatique des thèmes et d'une criticité, puis tri manuel.
4. **Analyse** : retour à la source primaire, rédaction d'une fiche.
5. **Diffusion** : ce site, sa synthèse hebdomadaire et son flux RSS.
6. **Ajustement** : revue trimestrielle des sources, des mots-clés et des règles de classement.

## Collecte

| Canal | Outil | Fréquence |
|---|---|---|
| Flux RSS / Atom | Pipeline GitHub Actions de ce site | Toutes les 6 heures |
| Vulnérabilités exploitées | Catalogue CISA KEV | Toutes les 6 heures |
| CVE critiques | API NVD 2.0 | Toutes les 6 heures |
| Correctifs de la pile IA | Notes de version GitHub filtrées sur « security », « CVE », « GHSA » | Toutes les 6 heures |
| Alertes par mots-clés | Alertes de moteurs de recherche, livrées en RSS | Quotidienne |
| Sources sans flux (ANSSI, CNIL, ENISA, NIST) | Consultation manuelle | Mensuelle |

Les flux de versions GitHub sont filtrés parce qu'ils annoncent toutes les versions, pas seulement les correctifs de sécurité. À l'inverse, un correctif publié sans CVE n'apparaît dans aucune base de vulnérabilités : suivre directement les dépôts des projets comble ce trou.

## Qualification

**Fiabilité de la source**

| Cote | Signification | Usage |
|---|---|---|
| A | Officielle ou primaire : CERT, autorité, éditeur du produit | Suffit seule |
| B | Chercheur ou éditeur reconnu | À citer avec sa date |
| C | Média spécialisé | À recouper avec une source A ou B |
| D | Blog, réseau social | Jamais utilisée seule |

**Criticité**

| Niveau | Règle automatique |
|---|---|
| Critique | Score CVSS ≥ 9, ou exploitation active, ou zero-day |
| Élevée | CVSS ≥ 7, alerte CERT, ajout au catalogue KEV, exécution de code à distance |
| Moyenne | CVSS ≥ 4 |
| Non évaluée | Actualité, recherche, réglementation : à qualifier à la main |

La criticité automatique est un **premier tri**. Dans une fiche, elle est réévaluée selon l'exposition réelle : conditions d'exploitation, droits nécessaires, données concernées.

**Pertinence**, évaluée dans chaque fiche :

| Note | Signification |
|---|---|
| 0 | Hors périmètre |
| 1 | Tendance générale, utile pour comprendre |
| 2 | Concerne un type de système ou de donnée couvert par la problématique |
| 3 | Concerne une brique logicielle couramment déployée dans ce contexte |

## Analyse : la fiche de veille

Chaque fiche suit le même plan :

- **En bref** : trois lignes, quoi, qui est concerné, ce qui a changé.
- **Faits** : uniquement des éléments vérifiés à la source primaire, avec versions et identifiants.
- **Analyse** : conditions d'exploitation, tendance à laquelle l'information se rattache, exposition type.
- **Recommandations** : action immédiate, puis mesure de fond.
- **Sources** : liens vers les sources primaires.

Règle de publication : les fiches restent génériques. Aucune information sur un établissement, une adresse, un nom de machine ou une personne.

## Rythme

| Fréquence | Activité |
|---|---|
| Quotidienne (10 à 15 min) | Lecture du [tableau de bord](#/), des entrées critiques et exploitées |
| Hebdomadaire | Relecture de la [synthèse de la semaine](#/hebdo), choix des sujets de fiche |
| Mensuelle | Sources manuelles, mise à jour de l'[agenda](#/agenda) |
| Trimestrielle | Revue des sources et des règles de classement |

## Indicateurs

- Nombre de sources suivies et taux de réponse à la collecte (vue [Méthode](#/methode)).
- Nombre d'entrées collectées et archivées.
- Nombre de fiches publiées par mois.
- Exemples où une information de veille a déclenché une vérification ou une action.

## Outillage

Le site est statique et ne dépend d'aucun service tiers en dehors de GitHub. Un script Python (bibliothèque standard uniquement) collecte les flux, attribue thèmes et criticité, garde une archive de 120 jours et convertit les fiches et pages Markdown en HTML. Le code est dans le dépôt du site.
