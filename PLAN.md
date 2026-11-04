# Plan d’implémentation — Liana Wallet Derivation TypeScript

## Objectif et périmètre

Construire un package ESM TypeScript pour Node.js ≥20.19 qui importe un descripteur Liana existant et dérive, en mode watch-only, les adresses Bitcoin et scriptPubKey exactement conformes à l’implémentation Rust épinglée. La spécification PDF fournie est le contrat de périmètre. La compatibilité ne sera pas revendiquée avant parité prouvée sur les politiques Taproot à clé primaire unique et multisig.

## Avancement constaté

- **Phase 0 — validée :** Liana v9.0 et Miniscript 11.2.0 sont épinglés ; la fixture Signet publique clé unique et cinq cas Rust (clé unique, multisig à une récupération, branches multipath distinctes, plusieurs récupérations, récupération Taproot `multi_a` avec plusieurs seuils) sont intégrés avec provenance. Le harness ne conserve que des xpubs/fingerprints publics.
- **Phase 1 — socle validé :** package ESM strict, CI, erreurs typées et installation `npm ci` reproductible ; audit npm courant sans vulnérabilités signalées.
- **Phase 2 — validée pour T01–T04 :** dérivation BIP32/BIP39, import xpub avec origines, dérivation publique non durcie et vérification réseau. Les tests couvrent le xpub officiel BIP32 vector 1, le tpub exact du chemin `m/48'/1'/0'/2'` cross-checké par Rust, les deux clés CKDpub branch 0/1 index 0 cross-checkées par Rust, et les vecteurs BIP39 anglais et japonais NFKD (wordlist explicite).
- **Phase 3 — toujours partielle :** import checksumé/lossless et parité exacte pour les formes testées, avec deux rejets sémantiques négatifs et un cas positif issus du parseur Rust. Le vecteur Signet `multi_a(1,key)` confirme un recovery à clé unique normalisé en `PathInfo::Single`, avec 20 sorties Rust exactes. Le vecteur Signet `<7;19>` confirme que receive/change sélectionne les valeurs multipath ordonnées (et non des numéros de branche supposés). Le validateur reste syntaxique et borné : il ne reproduit pas l’extraction/normalisation de `SemanticPolicy` de Liana pour toute la grammaire, tous les chemins d’origine et toutes les formes de clés internes.
- **Phase 4 — validée pour les vecteurs couverts :** 104 paires adresse/scriptPubKey concordent octet par octet avec Rust : 20 pour cinq politiques Taproot mainnet, 20 pour une politique Taproot Signet single-primary, 20 pour la même politique avec choix multipath `<7;19>`, 20 pour son recovery `multi_a(1,key)`, et 24 pour cinq formes P2WSH mainnet plus un descripteur P2WSH Signet exact sur indices 0–1 ; compatibilité générale non revendiquée.
- **Phase 5 — implémentée :** API et CLI watch-only testées, incluant receive/change.
- **Phase 6 — gates partielles :** 61 tests, `npm run typecheck`, `npm run build`, `npm audit --omit=dev` (0 vulnérabilités), `npm pack` réel (archive de 24 fichiers inspectée), `git diff --check` et la régénération byte-identique du nouveau fixture `multi_a(1,key)` sont vérifiés. `npm ci` avait été validé dans la tranche précédente ; les générateurs des anciens fixtures de rejet/multipath n’ont pas été relancés ici. La revue indépendante de cette tranche reste à faire. Le harness Rust dédié à la clé interne aplatie ou au signataire à branche fixe reste à enregistrer.

## Phase 0 — Références et critères de compatibilité

- Épingler une version/tag ou un commit précis de Liana et identifier la version exacte de miniscript utilisée ; consigner ces références.
- Étudier le parseur, l’analyse des descripteurs, le calcul de la clé NUMS et la dérivation effective des scripts/adresses côté Rust.
- Récupérer et archiver sans troncature la fixture Signet Liana v9 citée par la spécification ; relever ses descripteurs, adresses receive/change et scripts attendus.
- Intégrer des fixtures séparées pour clé primaire unique, multisig primaire avec une récupération et plusieurs chemins de récupération. Les résultats Rust sont l’oracle et chaque fixture garde sa provenance ; aucune valeur attendue n’est inventée.
- Définir les tests de parité et le blocage de version pour toute mise à jour cryptographique.

**Porte de sortie :** sources épinglées et fixtures dont la provenance et les valeurs attendues sont vérifiables.

## Phase 1 — Socle du dépôt et sécurité

- Finaliser package ESM, Node.js ≥20, TypeScript strict, scripts build/typecheck/test et verrouillage exact des dépendances.
- Ajouter README, licence, `.gitignore`, CI minimale (installation reproductible, typecheck, build, tests) et politique de divulgation des limites.
- Interdire l’inclusion de secrets/fixtures sensibles ; ne jamais journaliser ni persister mnémoniques, passphrases, graines ou clés privées.
- Définir des erreurs typées et diagnostiquables pour parsing, checksum, réseau, chemin et dérivation.

**Porte de sortie :** installation propre reproductible, build et CI verts.

## Phase 2 — Primitives BIP32 et origines de clés (P0)

- Implémenter/typeser les réseaux mainnet, testnet, signet et regtest ; le préfixe tpub ne suffit pas à distinguer les réseaux.
- Dériver une clé de compte depuis une seed et un chemin configurable ; prendre en charge BIP39 en option, passphrase et normalisation Unicode NFKD.
- Importer et valider xpub/tpub, fingerprint maître, chemin d’origine et métadonnées BIP32 ; préserver les informations d’origine complètes.
- Dériver uniquement les enfants publics non durcis `branche/index`, conserver la clé SEC compressée et produire la représentation x-only au bon stade.
- Vérifier les vecteurs officiels BIP32/BIP39 et erreurs : chemin durci en watch-only, index invalide, clé/pubkey invalide, version réseau incompatible.

**Porte de sortie :** T01–T04 et tests négatifs passent ; import et dérivation n’exposent pas de matière privée.

## Phase 3 — Descripteurs : analyse lossless et validation Liana (P0)

- Évaluer la parité de `@bitcoinerlab/descriptors` avec la version Liana/miniscript épinglée ; ne pas supposer qu’un parseur tiers suffit.
- Parser checksum, origines, clés étendues, multipath à deux choix, wildcard et syntaxe exacte acceptée par Liana.
- Préserver la chaîne originale, l’ordre des branches, l’ordre des clés, la topologie des arbres et les expressions de chaque chemin ; garder AST et texte source associés sans réécriture sémantique.
- Mapper `receive`/`change` vers les deux valeurs multipath présentes dans le descripteur, même si elles ne sont pas 0 et 1.
- Rejeter explicitement checksum absent/invalide selon le contrat retenu, origines absentes, dérivations durcies publiques, réseau incompatible, politiques invalides et doublons interdits par la référence.

**Avancement — toujours partiel :** le parseur importe sans réécriture les fixtures exactes pour les formes documentées, et le test indépendant de `@bitcoinerlab/descriptors` reproduit les 64 paires de ses fixtures. Un fixture Rust positif additionnel vérifie le candidat `multi_a(1,key)` : `LianaDescriptor::from_str` l’accepte, infère un recovery à clé unique (`PathInfo::Single`) à `older(36)`, et dérive 20 sorties Signet exactes. Un autre fixture vérifie 20 sorties pour `<7;19>`. Deux contre-exemples Taproot avec hashlock, rejetés par `LianaDescriptor::from_str` épinglé, sont également rejetés par TypeScript. Des tests négatifs dérivés de fixtures Rust couvrent la clé interne spendable aplatie et un signataire de récupération à branche fixe dans un descripteur multipath ; ce dernier suit le contrat source de `DescKeyChecker::check`, mais n’a pas encore son propre résultat/harness Rust enregistré. Un test source-derived supplémentaire rejette la même identité de clé xpub/chemin entre primaire et récupération malgré des fingerprints différents ; il n’a pas de vecteur Rust dédié. Les descripteurs communautaires à branches fixes sans multipath restent acceptés. L’adaptateur classe encore les chemins par syntaxe (`pk`/`multi_a` et `and_v(...,older())`) au lieu de reproduire l’analyse/normalisation `SemanticPolicy` de Liana. Restent notamment la classification exacte des politiques normalisées, les formes de clé interne hors de ces cas et une parité sémantique plus large.

**Porte de sortie :** non satisfaite tant que l’analyse sémantique et les règles de clés/chemins ne concordent pas avec la référence épinglée pour toute la grammaire visée par cette phase. Les 64 paires du test de parité de la bibliothèque et les fixtures Rust `multi_a(1,key)`/`<7;19>` ne démontrent que les cas couverts ; elles ne prouvent pas une compatibilité générale. Continuer avec des vecteurs Rust valides et invalides avant d’élargir ou de fermer la phase.

## Phase 4 — Taproot Liana et adresses exactes (P0)

- Reproduire l’analyse du descripteur et la clé interne pour chaque forme de politique ; pour multisig, implémenter la construction NUMS et la chain code SHA256 selon l’ordre exact des clés rencontrées dans les feuilles.
- Dériver chaque clé au couple branche/index tout en conservant sa position, puis interpréter exactement Miniscript/Tapscript et la topologie de l’arbre.
- Calculer TapLeaf, TapBranch, TapTweak, clé x-only de sortie, scriptPubKey P2TR et adresse Bech32m selon le réseau.
- Comparer octet par octet scriptPubKey et chaîne d’adresse aux résultats du Liana/Rust épinglé, sur plusieurs index receive et change.
- Ne pas reconstruire un descripteur depuis une politique relevée ; ne pas trier les feuilles, remplacer l’arbre, ou inférer timelocks et politique.

**Porte de sortie :** T05–T11 pertinents passent ; parité démontrée pour clé primaire unique et multisig primaire avec récupération(s), sur plusieurs branches/index. Sans cela, ne pas annoncer la compatibilité Liana.

## Phase 5 — API publique et CLI

- Exposer les types et fonctions de la spécification : `deriveAccountXpub`, `importAccountXpub`, `deriveChildKey`, `parseLianaDescriptor`, `deriveWalletAddress`.
- Garantir des buffers typés prévisibles, erreurs publiques documentées et interface de dérivation watch-only.
- Ajouter une CLI pour importer un descripteur, choisir explicitement le réseau et lister des plages receive/change avec adresse et scriptPubKey ; ne pas afficher ni demander de secrets pour un import de descripteur watch-only.
- Documenter exemples, réseaux, sens des branches, limites de compatibilité, installation et provenance des fixtures.

**Porte de sortie :** tests API/CLI de bout en bout passent ; déclarations TypeScript générées et vérifiées.

## Phase 6 — Vérification finale et version initiale

- Exécuter sur installation propre : tests unitaires, tests de parité Liana, tests négatifs, typecheck, build et CLI.
- Auditer les dépendances et le contenu Git ; s’assurer qu’aucun secret ou résultat attendu non sourcé n’est inclus.
- Publier un rapport de compatibilité indiquant les versions Liana/miniscript testées et les politiques réellement validées.
- Taguer une version initiale uniquement si toutes les portes P0 sont satisfaites ; sinon livrer comme expérimental avec les lacunes explicitement listées.

## Ordre de commits proposé

Un commit distinct par étape validée : `chore` socle, `test` fixtures/oracle, `feat` primitives BIP32, `feat` parser, `feat` Taproot/parité, `feat` API/CLI, puis `docs` vérification/version. Ne pas regrouper une étape non validée dans un commit présenté comme achevé.

## Risques majeurs

- Le parseur ou compilateur Miniscript tiers peut accepter une grammaire ou une sémantique différente de Liana.
- La dérivation NUMS dépend de l’ordre concret d’itération des clés dans la version Rust épinglée.
- Une fixture communautaire peut être incomplète ou ne pas suffire à couvrir les variantes ; obtenir des vecteurs supplémentaires depuis Liana est alors un préalable au claim de compatibilité.
- Les clés publiques et descripteurs révèlent des métadonnées financières : protéger également fixtures et logs.
