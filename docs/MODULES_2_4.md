# Modules 2 et 4 - Utilisateurs et intégrité des fichiers

Ce document récapitule les deux modules attribués à Tom :

- **Module 2** : activité des utilisateurs et authentification ;
- **Module 4** : intégrité des fichiers et recherche de mécanismes de persistance.

Les deux modules suivent le contrat du projet : une seule fonction publique,
affichage par `kv()` et `ok()`, alertes par `alert()`, seuils et listes dans
`hids.conf`, et aucun accès direct aux fichiers de journalisation du HIDS.

## Utilisation

Créer d'abord l'état de référence :

```bash
sudo ./hids.sh --baseline
```

Lancer les deux modules dans une analyse complète :

```bash
sudo ./hids.sh
```

Lancer un seul module :

```bash
sudo ./hids.sh --module 2
sudo ./hids.sh --module 4
```

L'exécution avec `sudo` est recommandée. Sans les droits root, le module 2 ne
peut généralement pas lire `/etc/shadow` et `btmp`, et le module 4 ne peut pas
calculer le hash de tous les fichiers protégés ni parcourir tout le système.

# Module 2 - Activité des utilisateurs

## Objectif

Le module 2 répond à la question : **qui utilise la machine et cette activité
est-elle normale ?**

Sa fonction publique est :

```bash
run_user_activity
```

Elle exécute successivement la collecte des événements d'authentification, les
contrôles de connexions, les contrôles de comptes et la comparaison avec la
baseline.

## Sources analysées

| Source | Information obtenue |
|---|---|
| `AUTH_LOG` dans `hids.conf` | Échecs et réussites SSH sur Ubuntu/Debian |
| `journalctl -u sshd -u ssh` | Événements SSH sur Fedora et systèmes journald |
| `last` / `wtmp` | Connexions réussies de la journée |
| `lastb` / `btmp` | Historique des connexions échouées |
| `who` / `utmp` | Sessions actuellement ouvertes |
| `/etc/passwd` | Comptes, UID, GID, répertoires personnels et shells |
| `/etc/shadow` | État et vieillissement des mots de passe, sans conserver les hashes |
| `getent group sudo/wheel` | Existence, GID et membres des groupes administrateurs |

Le module privilégie le fichier `AUTH_LOG` lorsqu'il est configuré et lisible.
Sinon, il utilise automatiquement journald. Cette stratégie rend le module
compatible avec Ubuntu et Fedora.

## Collecte et parsing SSH

En analyse normale, `user_load_auth_events()` ne conserve que les événements
de la journée courante :

- filtrage de la date syslog pour `AUTH_LOG` ;
- option `--since today` pour journald.

Pendant une capture de baseline, l'historique disponible est chargé sans ce
filtre afin d'enrichir la liste des IP SSH approuvées. Une erreur de lecture
est signalée et fait passer la couverture du module à `partial`.

Les fonctions de parsing cherchent les mots-clés OpenSSH au lieu de dépendre
de numéros de champs fixes :

```text
Failed password for tom from 192.0.2.10 port 22 ssh2
Failed password for invalid user admin from 192.0.2.20 port 22 ssh2
Accepted publickey for tom from 192.0.2.30 port 22 ssh2
```

Le parseur reconnaît aussi les échecs PAM, les dépassements du nombre de
tentatives et les déconnexions d'utilisateurs invalides ou en cours
d'authentification. Il extrait et valide les adresses IPv4 et IPv6, puis
normalise chaque événement en succès ou échec. Les lignes reconnues mais
incomplètes sont comptées séparément comme non parsées.

## Contrôles réalisés

### Échecs d'authentification

`user_alert_failed_logins()` :

- compte les événements SSH suspects de la journée ;
- les regroupe par adresse IP source ;
- compare chaque total aux seuils configurés ;
- détecte un volume global élevé réparti entre plusieurs sources ;
- compte, pour chaque compte ciblé, le nombre d'IP distinctes utilisées.

`user_check_login_history()` agrège séparément `wtmp` et `btmp` comme contexte
et indique explicitement lorsqu'une source n'est pas accessible.

Les seuils viennent de `hids.conf` :

- `FAILED_LOGIN_WARN` : déclenche une alerte `HIGH` ;
- `FAILED_LOGIN_CRIT` : déclenche une alerte `CRITICAL`.

### Connexions réussies

`user_check_successful_logins()` :

- extrait les IP des authentifications SSH acceptées ;
- compare ces IP à la baseline ;
- détecte les connexions hors horaires de travail.

L'historique `wtmp`, affiché par `user_check_login_history()`, ignore les
pseudo-entrées telles que `reboot`, `shutdown` et `wtmp begins`.

Les horaires autorisés sont définis par `WORK_HOURS_START` et
`WORK_HOURS_END` dans `hids.conf`. La borne de fin est exclusive : avec une fin
à `20`, une connexion à partir de 20 h est considérée hors horaires.

### Sessions actives

`user_check_current_sessions()` utilise `who` pour compter les sessions
actuellement enregistrées dans `utmp` et les regrouper par utilisateur.

### Comptes UID 0

`user_check_uid_zero()` lit le troisième champ de `/etc/passwd`. Tout compte UID 0
autre que `root` reçoit une alerte critique, car il possède tous les privilèges
root.

### Évolution des comptes et identifiants dupliqués

`user_check_accounts()` compare pour chaque compte le nom, l'UID, le GID, le
répertoire personnel et le shell avec la baseline. Il détecte :

- la création et la suppression d'un compte ;
- une modification d'UID, de GID, de répertoire personnel ou de shell ;
- l'attribution d'un shell interactif à un compte système auparavant bloqué.

`user_check_uid_gid_duplicates()` signale aussi les UID partagés entre
plusieurs comptes et les GID utilisés par plusieurs définitions de groupes.

### Mots de passe vides

`user_check_shadow()` lit le deuxième champ de `/etc/shadow`. Un champ vide est
critique, car le compte peut accepter une authentification sans mot de passe
selon la configuration PAM. Le module compare également l'état des mots de
passe et leurs paramètres de vieillissement à la baseline afin de détecter le
déverrouillage d'un compte et la suppression d'une expiration.

Si `/etc/shadow` n'est pas lisible, le module signale que le contrôle nécessite
root sans interrompre l'analyse et marque sa couverture comme partielle.

Les valeurs `!`, `!!`, `*` et les hashes ne sont pas considérés comme vides.

### Groupes administrateurs

`user_check_privileged_groups()` prend en charge :

- `sudo` sur Ubuntu/Debian ;
- `wheel` sur Fedora.

Il rassemble les membres explicitement inscrits dans le groupe et les comptes
dont ce groupe est le groupe principal. Il détecte les ajouts et retraits de
membres, ainsi que la création, la suppression ou le changement de GID d'un
groupe privilégié.

## Baseline du module 2

Le mode `--baseline` enregistre quatre snapshots atomiques au format versionné
`VERSION|2|TYPE` :

| Baseline | Contenu |
|---|---|
| `user_login_ips` | IP ayant réussi une authentification SSH ; les nouvelles valeurs sont fusionnées avec la liste approuvée existante |
| `user_accounts` | Nom, UID, GID, répertoire personnel et shell de chaque compte |
| `user_shadow_state` | État `EMPTY`, `LOCKED` ou `ACTIVE` et paramètres de vieillissement, sans stocker les hashes |
| `user_privileged_members` | Existence, GID et membres complets de `sudo` et `wheel` |

Les fichiers sont écrits avec le mode `600` puis publiés par renommage. Pendant
la capture, le module n'émet pas d'alerte. Une baseline absente ou d'une
ancienne version n'est jamais comparée et le rapport demande sa recapture.

## Validation et couverture du module 2

Avant l'analyse, le module vérifie ses commandes natives et valide les quatre
seuils numériques de `hids.conf`, notamment leur ordre et les bornes horaires.
Son résumé indique les événements SSH parsés et non parsés, les sessions,
comptes et membres privilégiés contrôlés, le nombre d'alertes du module et une
couverture `complete` ou `partial`.

## Codes d'alerte du module 2

| Code | Sévérité | Signification |
|---|---|---|
| `USR-001` | `CRITICAL` | Compte UID 0 autre que `root` |
| `USR-002` | `HIGH` ou `CRITICAL` | Nombre excessif d'événements SSH suspects depuis une IP |
| `USR-003` | `HIGH` | Nouveau compte depuis la baseline |
| `USR-004` | `CRITICAL` | Champ mot de passe vide dans `/etc/shadow` |
| `USR-005` | `HIGH` | Nouveau membre de `sudo` ou `wheel` |
| `USR-006` | `HIGH` | Connexion SSH réussie depuis une nouvelle IP |
| `USR-007` | `MEDIUM` | Connexion SSH hors horaires autorisés |
| `USR-008` | `MEDIUM` | Compte supprimé depuis la baseline |
| `USR-009` | `MEDIUM` ou `HIGH` | Propriétés d'un compte modifiées ; sévérité haute si un compte système obtient un shell interactif |
| `USR-010` | `MEDIUM` | Membre retiré de `sudo` ou `wheel` |
| `USR-011` | `HIGH` | État ou GID d'un groupe privilégié modifié |
| `USR-012` | `HIGH` | UID partagé entre plusieurs comptes |
| `USR-013` | `MEDIUM` | GID partagé entre plusieurs définitions de groupes |
| `USR-014` | `HIGH` | Compte auparavant verrouillé devenu actif |
| `USR-015` | `MEDIUM` | Expiration du mot de passe assouplie |
| `USR-016` | `HIGH` ou `CRITICAL` | Volume global excessif d'événements SSH suspects |
| `USR-017` | `HIGH` ou `CRITICAL` | Compte SSH ciblé depuis de nombreuses IP distinctes |

# Module 4 - Intégrité des fichiers

## Objectif

Le module 4 répond à la question : **un fichier sensible, un binaire privilégié
ou un mécanisme de démarrage a-t-il été modifié de manière suspecte ?**

Sa fonction publique est :

```bash
run_file_integrity
```

En mode baseline, elle capture le contenu et les métadonnées des chemins
surveillés ainsi que les fichiers SUID/SGID. En mode normal, elle exécute tous
les contrôles d'intégrité.

## Configuration utilisée

| Variable | Rôle |
|---|---|
| `WATCHED_FILES` | Chemins dont l'état, le contenu, les métadonnées et le type sont surveillés |
| `SENSITIVE_FILE_MODES` | Permissions maximales admises par fichier sensible |
| `FIND_EXCLUDE` | Arborescences exclues des recherches globales |
| `SUID_WHITELIST` | Nouveaux exécutables SUID/SGID explicitement acceptés |

La configuration actuelle surveille notamment `/etc/passwd`, `/etc/shadow`,
`/etc/group`, `/etc/sudoers`, la configuration SSH, `/etc/crontab`,
`/etc/hosts`, les fichiers de démarrage root et `authorized_keys`.

## Baseline du module 4

`build_baseline()` crée deux snapshots :

| Baseline | Contenu |
|---|---|
| `file_hashes` | État, SHA-256, mode, UID, GID, taille, date de modification, type et cible de lien de chaque chemin surveillé |
| `suid_binaries` | Liste triée des exécutables SUID/SGID avec SHA-256, UID et mode |

Pour chaque chemin surveillé, `file_hash_snapshot()` enregistre l'un des états
suivants :

- `PRESENT` pour un fichier régulier lisible, avec son hash SHA-256 ;
- `MISSING` si le chemin n'existe pas ;
- `UNREADABLE` s'il existe mais ne peut pas être lu ;
- `SYMLINK` avec la cible du lien ;
- `SPECIAL` pour un chemin existant qui n'est ni un fichier régulier ni un
  lien symbolique.

Enregistrer les fichiers absents permet aussi de détecter leur création
ultérieure. Les chemins et cibles sont encodés en base64 pour préserver les
espaces et les délimiteurs.

Les deux snapshots utilisent le format versionné `VERSION|2|TYPE`, sont écrits
avec le mode `600` et publiés par renommage atomique. Une collecte SUID/SGID
ayant rencontré des erreurs est conservée avec un marqueur
`COLLECTION|PARTIAL` afin que sa couverture ne soit pas présentée comme
complète.

## Contrôles réalisés

### Comparaison des hashes

`check_file_hashes()` recalcule l'état de chaque chemin et le compare à la
baseline. Il détecte :

- une modification de contenu ;
- la suppression d'un fichier ;
- la création d'un fichier auparavant absent ;
- un changement de lisibilité ;
- un changement de type ou de cible de lien symbolique ;
- un changement de propriétaire, de groupe ou de mode ;
- un changement de taille ou de date sans changement de hash ;
- un chemin ajouté à `WATCHED_FILES` ou retiré de cette configuration depuis
  la baseline.

Sans baseline, aucune alerte n'est générée et le rapport demande d'exécuter
`./hids.sh --baseline`.

### Permissions des fichiers sensibles

`check_permissions()` utilise `stat` et `SENSITIVE_FILE_MODES`. Il compare les
bits de permission plutôt que la valeur octale comme un simple nombre. Une
permission plus restrictive est affichée comme contexte ; tout bit accordant
plus de droits que prévu déclenche une alerte.

Exemple : un `/etc/shadow` en `600` est plus restrictif que `640`, tandis qu'un
mode `644` rend le fichier lisible par tous et est dangereux.

### Fichiers privilégiés SUID/SGID

`check_suid_binaries()` recherche les exécutables portant le bit SUID ou SGID.
Les chemins virtuels, temporaires ou de conteneurs configurés dans
`FIND_EXCLUDE` sont élagués, et `-xdev` empêche de traverser d'autres systèmes
de fichiers.

Chaque fichier privilégié absent de la baseline est :

- affiché comme exception s'il appartient à `SUID_WHITELIST` ;
- signalé comme anomalie dans le cas contraire.

Le contrôle détecte également la modification du hash, du propriétaire ou du
mode, la disparition d'un exécutable privilégié, l'absence de bit exécutable et
un répertoire parent modifiable par le groupe ou par tous. Si la collecte
courante est partielle, les alertes de disparition sont désactivées pour éviter
les faux positifs.

### Fichiers world-writable

`check_world_writable()` recherche les fichiers ordinaires modifiables par tous
dans les répertoires sensibles dérivés de `WATCHED_FILES`. Un tel fichier peut
permettre à un utilisateur non autorisé d'altérer une configuration ou un
exécutable. Les erreurs de parcours sont comptées et rendent la couverture
partielle.

### Changements depuis la baseline

`check_recent_changes()` compare la date de modification actuelle de chaque
chemin surveillé à celle enregistrée dans `file_hashes`. Il affiche les chemins
modifiés depuis la baseline et leur nombre. Ce résultat est un contexte
d'investigation, pas une anomalie supplémentaire à lui seul.

### Persistance dans les fichiers de démarrage

`check_startup_files()` inspecte les chemins configurés se terminant par :

- `.bashrc` ;
- `.profile` ;
- `authorized_keys`.

Il ignore les lignes commentées et recherche des motifs à fort signal :

- shell interactif `bash -i` associé à `/dev/tcp/` ou `/dev/udp/` ;
- téléchargement avec `curl` ou `wget` suivi d'une exécution par un shell ;
- décodage base64 suivi d'une exécution par un shell ;
- utilisation de `nc`, `ncat` ou `netcat` avec une option d'exécution ;
- options restrictives ou d'exécution dans `authorized_keys`, telles que
  `command=`, `environment=` et `permitopen=`.

Chaque résultat inclut le chemin et le numéro de ligne.

## Validation et couverture du module 4

Le module vérifie la présence de ses commandes natives avant de commencer. Son
résumé indique le nombre de chemins surveillés, fichiers lisibles, absents et
illisibles, exécutables SUID/SGID contrôlés, alertes produites et une couverture
`complete` ou `partial`. Une baseline absente ou obsolète est ignorée et une
recapture est demandée.

## Codes d'alerte du module 4

| Code | Sévérité | Signification |
|---|---|---|
| `FIM-001` | `HIGH` | Permissions plus larges que la politique configurée |
| `FIM-002` | `HIGH` | Changement de contenu, de présence ou de lisibilité |
| `FIM-003` | `HIGH` | Nouveau fichier SUID/SGID non autorisé |
| `FIM-004` | `HIGH` | Fichier world-writable dans un répertoire sensible configuré |
| `FIM-005` | `HIGH` | Motif de persistance dans un fichier de démarrage |
| `FIM-006` | `HIGH` | Type de fichier ou cible de lien symbolique modifié |
| `FIM-007` | `HIGH` | Propriétaire ou groupe d'un chemin surveillé modifié |
| `FIM-008` | `HIGH` | Mode d'un chemin surveillé modifié |
| `FIM-009` | `MEDIUM` | Taille ou date modifiée sans changement de hash |
| `FIM-010` | `MEDIUM` | Chemin retiré de `WATCHED_FILES` depuis la baseline |
| `FIM-011` | `HIGH` | Hash, propriétaire ou mode d'un exécutable SUID/SGID modifié |
| `FIM-012` | `MEDIUM` | Exécutable SUID/SGID disparu depuis la baseline |
| `FIM-013` | `HIGH` | Fichier SUID/SGID sans bit exécutable |
| `FIM-014` | `HIGH` | Exécutable privilégié placé dans un répertoire modifiable par le groupe ou par tous |

# Complémentarité des deux modules

Les modules 2 et 4 couvrent ensemble plusieurs scénarios d'intrusion :

| Scénario | Module 2 | Module 4 |
|---|---|---|
| Création d'un compte caché | Nouveau compte ou UID 0 | Modification de `/etc/passwd` et `/etc/shadow` |
| Ajout de privilèges administrateur | Nouveau membre `sudo`/`wheel` | Modification de `/etc/group` ou `/etc/sudoers` |
| Vol ou ajout de clé SSH | Nouvelle IP de connexion | Modification de `authorized_keys` |
| Brute force SSH | Échecs regroupés par IP | Sans objet |
| Persistance shell | Sans objet | Motifs suspects dans `.bashrc` et `.profile` |
| Élévation locale | Compte privilégié | Nouveau binaire SUID ou permissions dangereuses |

Cette redondance est volontaire : une même attaque laisse souvent plusieurs
traces indépendantes. Une création de compte, par exemple, peut produire une
alerte comportementale dans le module 2 et une alerte d'intégrité dans le
module 4.

# Limites connues

- La baseline doit être capturée sur une machine considérée saine.
- Un attaquant root capable de modifier la baseline peut masquer ses changements.
- Les événements SSH supprimés avant l'analyse ne peuvent plus être détectés.
- Le contrôle des nouvelles IP porte sur les événements de la journée analysée.
- Les motifs de persistance peuvent produire des faux positifs légitimes.
- `-xdev` améliore les performances, mais exclut les autres systèmes de fichiers.
- Une surveillance périodique ne remplace pas un mécanisme temps réel comme
  Auditd, inotify ou un agent HIDS dédié.
