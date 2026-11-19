---
title: L'IA en santé mentale, surface d'attaque et levier de défense
nav: true
nav_label: Problématique
order: 10
summary: Le fil conducteur de cette veille : ce que l'arrivée de l'IA générative change pour la sécurité des établissements de santé mentale.
updated: 2026-11-19
---

## La question

> Dans un établissement de santé mentale, l'IA est à la fois une **nouvelle surface d'attaque** sur des données parmi les plus sensibles qui soient, et un **levier pour renforcer la cybersécurité**. Comment en tirer parti tout en maîtrisant les risques ?

## Pourquoi ce sujet

- **Des données à part.** En psychiatrie, un dossier contient des éléments de vie intime, des antécédents, parfois des mesures de soins sans consentement. Ce sont des données de santé au sens de l'article 9 du RGPD, et leur divulgation a des conséquences personnelles lourdes.
- **Une adoption rapide.** Transcription automatique des consultations, synthèse de dossiers, recherche dans les protocoles, questions en langage naturel sur les données : les cas d'usage arrivent vite, souvent avant les règles qui les encadrent.
- **Des usages non encadrés.** Un service d'IA grand public est à un copier-coller de distance. Sans outil interne ni charte, le risque de fuite se déplace vers des services hors de tout contrôle.
- **Un cadre qui bouge.** AI Act, transposition de NIS 2, doctrine ANSSI et CNIL : les obligations évoluent pendant que les projets se déploient (voir l'[agenda](#/agenda)).
- **Un outil pour les défenseurs.** Les mêmes modèles aident à lire des journaux, auditer du code ou trier des alertes, à condition de les concevoir pour ne rien laisser fuir.

## Les axes de veille

| Axe | Ce qui est suivi | Exemples de mots-clés |
|---|---|---|
| **A. Menaces sur l'IA** | Nouvelles attaques contre les applications à base de LLM, incidents réels | prompt injection, injection indirecte, jailbreak, empoisonnement de RAG, agents, MCP |
| **B. Protéger l'IA** | Garde-fous, pseudonymisation, traçabilité, cloisonnement, tests offensifs | guardrails, Presidio, observabilité LLM, red teaming |
| **C. L'IA pour la défense** | Analyse de journaux, aide au SOC, audit de code, et usages offensifs par les attaquants | copilote SOC, analyse de logs, hameçonnage généré, deepfake vocal |
| **D. Cadre et santé** | Réglementation, doctrine, incidents dans le secteur de la santé | AI Act, NIS 2, RGPD, HDS, CERT Santé |
| **E. Pile IA open source** | Vulnérabilités et correctifs des briques souvent auto-hébergées | vLLM, Ollama, Qdrant, Langfuse, Presidio |

Sur le site, ces axes se retrouvent dans les [thèmes du flux](#/flux), en particulier *Sécurité de l'IA*, *Santé* et *Réglementation*.

## Questions de recherche

1. Quelles attaques visent concrètement les applications d'IA qui manipulent des documents ou des conversations de soin, et lesquelles ont déjà été observées ?
2. Héberger les modèles soi-même réduit-il vraiment le risque, ou le déplace-t-il vers l'infrastructure, les intégrations et la traçabilité ?
3. Quelles mesures techniques et organisationnelles rendent un usage de l'IA défendable devant un patient, un DPO ou un auditeur ?
4. Dans quelles conditions un assistant IA peut-il aider une équipe sécurité sans devenir lui-même un point de fuite ?
5. Que changent l'AI Act et NIS 2 pour un établissement de santé qui déploie ses propres outils d'IA ?

## Ce que cette veille n'est pas

- Une analyse d'un établissement particulier : les fiches restent générales et ne décrivent aucun système interne.
- Un avis clinique sur l'usage de l'IA en psychiatrie : l'angle est celui de la sécurité de l'information.

## Pour aller plus loin

- [Méthodologie de la veille](#/p/methodologie)
- [Fiches d'analyse](#/fiches)
- [Synthèses hebdomadaires](#/hebdo)
