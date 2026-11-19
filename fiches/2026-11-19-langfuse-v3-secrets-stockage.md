---
title: Langfuse v3 — réutilisation des secrets de stockage après changement de destination
date: 2026-11-19
themes: [ia, vuln]
cote: A
criticite: À évaluer
summary: Un correctif « security » sans CVE, publié en v3.227.1, empêche de rediriger l'export des traces LLM vers une destination contrôlée par un tiers en réutilisant les identifiants enregistrés.
draft: true
---

<!-- BROUILLON : seuls les faits publics sont remplis. Rédiger « En bref », « Analyse » et « Recommandations », puis passer draft à false. -->

## En bref

_À rédiger._

## Faits

- **Composant** : Langfuse, plateforme open source de traçabilité des applications LLM, souvent auto-hébergée.
- **Fonction touchée** : l'export planifié vers un stockage objet (Blob Storage export : S3, S3 compatible, GCS, Azure), disponible sur toutes les éditions auto-hébergées v3. Sur la branche principale (v4), la fonction External Media Storage est aussi concernée.
- **Défaut** : lors de la modification d'une intégration, un champ secret laissé vide entraînait la réutilisation du secret enregistré, **même si la destination changeait** (fournisseur, bucket, endpoint ou identifiant de clé).
- **Conséquence** : une personne autorisée à modifier l'intégration (interface ou API publique `PUT /api/public/integrations/blob-storage`) pouvait rediriger l'export vers une destination qu'elle contrôle ; Langfuse y signait les requêtes avec les identifiants enregistrés.
- **Correctif** : tout changement de destination exige de ressaisir le secret (réponse `BAD_REQUEST` sinon).
- **Versions** : branche principale via la PR #19566 (fusionnée le 03/11/2026) ; branche v3 en **v3.227.1** via la PR #19817 (10/11/2026).
- **Identifiant** : aucun CVE ni avis GHSA publié au 19/11/2026.
- **Classe de défaut** : les PR citent un correctif antérieur du même type sur les destinations webhook et PostHog.

## Analyse

_À rédiger._

## Recommandations

_À rédiger._

## Sources

- [Notes de version v3.227.1](https://github.com/langfuse/langfuse/releases/tag/v3.227.1)
- [PR #19817 — rétroportage v3](https://github.com/langfuse/langfuse/pull/19817)
- [PR #19566 — correctif principal](https://github.com/langfuse/langfuse/pull/19566)
- [Avis de sécurité Langfuse](https://github.com/langfuse/langfuse/security/advisories)
