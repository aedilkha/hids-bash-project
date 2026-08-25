# Organisation de l'équipe — Projet HIDS

3 personnes, 1 semaine. Ce document évite le problème n°1 des projets Bash en
équipe : trois scripts qui ne parlent pas la même langue et qu'on n'arrive
plus à assembler le jour de la démo.

## La règle d'or

Un module = une personne = un fichier = une fonction publique.

Personne ne touche au fichier d'un autre. Personne ne modifie lib/common.sh
sauf le responsable du socle (Alvi). Si tu as besoin d'un truc dans le socle,
tu le demandes, tu ne l'ajoutes pas toi-même — sinon deux personnes réécrivent
la même fonction et git n'arrive plus à merger.

## Le contrat (non négociable)

Chaque module respecte exactement ça, sinon il ne s'intègre pas :

1. Fichier : modules/0X_nom.sh
2. Une seule fonction publique : run_<nom> (déjà nommée dans le squelette)
3. Toute anomalie passe par : alert SEVERITE CODE CLE MESSAGE
4. Tout contexte factuel passe par : kv "clé" "valeur"  ou  ok "message"
5. AUCUN echo >> fichier.log : seul alert() écrit dans les logs
6. AUCUN seuil ni whitelist codé en dur : tout va dans hids.conf
7. Préfixe de code d'alerte réservé au module (SYS / USR / PRC-NET / FIM)

Tant que ces 7 points sont respectés, ton module marchera avec ceux des autres
sans qu'on ait rien à recoller.

## Répartition

### Alvi — Socle + Module 1 + intégration
- lib/common.sh (fait) — tu es le SEUL à le modifier
- hids.sh (fait) — orchestrateur
- modules/01_system_health.sh (fait, sert de modèle aux autres)
- hids.conf (fait) — tu arbitres les ajouts de seuils
- Jour 6 : cron / systemd timer, baseline globale
- Jour 7 : tools/simulate_attack.sh (le script de démo)
- Tu fais les code reviews des deux autres avant merge

### Tom — Module 2 (Utilisateurs) + Module 4 (Fichiers)
- modules/02_user_activity.sh — checklist dans le fichier
- modules/04_file_integrity.sh — checklist dans le fichier
- Ces deux-là vont ensemble (auth.log + authorized_keys se recoupent)
- Livrable perso : les sections "users" et "fichiers" du research.md

### Jakub — Module 3 (Processus/Réseau) + README
- modules/03_process_network.sh — checklist dans le fichier
- README.md complet (public visé : un admin qui n'a pas codé l'outil)
- Livrable perso : la section "processus & réseau" du research.md
- C'est le module le plus dense : d'où le README au lieu d'un 2e module

Pourquoi 2 modules pour le membre 2 et 1 seul pour le membre 3 : le module 3
(parsing /proc, ss, whitelist de ports) prend autant de temps que deux autres.
Le README est un gros livrable écrit, ça équilibre la charge.

## Workflow git (pour ne jamais se marcher dessus MAIS PAS OBLIGATOIRE)

    main          <- ne reçoit que du code testé
      |-- module-2 <- branche de Tom
      |-- module-3 <- branche de Jakub
      |-- socle    <- branche de Alvi

- Chacun bosse sur SA branche, sur SON fichier
- Comme personne ne touche au même fichier, il n'y a jamais de conflit
- Merge vers main seulement après ./hids.sh --module X réussi
- Un commit par fonction terminée, message clair ("M3: check_listening_ports")

## Comment tester ton module isolément

    ./hids.sh --module 2      # ne lance que le module 2
    ./hids.sh --module 3      # ne lance que le module 3

Tu n'as pas besoin que les autres aient fini pour tester le tien.

## Définition de "terminé" pour un module

- [ ] Toutes les fonctions de la checklist du fichier sont écrites
- [ ] Chaque fonction a un commentaire : ce qu'elle fait ET où elle prend l'info
- [ ] ./hids.sh --module X tourne sans erreur en root ET en non-root
- [ ] Le module déclenche bien une alerte quand tools/simulate_attack.sh
      injecte la menace correspondante
- [ ] Zéro seuil en dur, zéro chemin de log en dur
- [ ] Reviewé par Alvi, mergé sur main

## Points de synchro (15 min, pas plus)

- Fin jour 1 : research.md validé, contrat compris par tous
- Fin jour 3 : chacun a au moins 2 fonctions qui marchent
- Fin jour 5 : tous les modules mergés sur main
- Jours 6-7 : ensemble sur baseline, cron, démo