# OSQuery CVE Validation & Infrastructure Mapping
## Security Reference Guide — Windows & Linux

---

## Getting Started — OSQuery Interactive Shell

Launch the interactive shell:
```bash
osqueryi
```

### Essential Meta-Commands

| Command | Description |
|---|---|
| `.help` | Show all available meta-commands |
| `.tables` | List all available tables |
| `.tables <keyword>` | Filter tables by keyword (e.g. `.tables process`) |
| `.schema <table>` | Show columns and data types for a table |
| `.all <table>` | Quick `SELECT *` from a table |
| `.mode pretty` | Default display — formatted table output |
| `.mode csv` | Output as comma-separated values |
| `.mode line` | One value per line (useful for wide tables) |
| `.mode column` | Left-aligned columns (use with `.width`) |
| `.timer ON` | Show query execution time |
| `.headers ON\|OFF` | Toggle column headers |
| `.quit` or `.exit` | Exit the shell |

### Basic Query Syntax
```sql
-- Select specific columns
SELECT column1, column2 FROM table_name;

-- Filter results
SELECT column1, column2 FROM table_name WHERE column1 = 'value';

-- Search with wildcard
SELECT column1 FROM table_name WHERE column1 LIKE '%keyword%';

-- Sort results
SELECT column1, column2 FROM table_name ORDER BY column1;

-- Limit results
SELECT column1 FROM table_name LIMIT 10;
```

### Quick Example Workflow
```sql
-- 1. Find tables related to a topic
osquery> .tables user

-- 2. Inspect the table schema
osquery> .schema users

-- 3. Query the table
osquery> SELECT uid, username, description, directory FROM users;
```

> **Note:** SQL queries require a semicolon `;` at the end. Meta-commands (prefixed with `.`) do not.

---

## Table of Contents

1. [OS Version Vulnerabilities](#1-os-version-vulnerabilities)
2. [Installed Software & Packages](#2-installed-software--packages)
3. [Running Processes & Services](#3-running-processes--services)
4. [Network Exposure](#4-network-exposure)
5. [User & Privilege Escalation Risks](#5-user--privilege-escalation-risks)
6. [Kernel & Drivers](#6-kernel--drivers)
7. [Scheduled Tasks & Persistence](#7-scheduled-tasks--persistence)
8. [IIS Web Server & Application Components](#8-iis-web-server--application-components)
9. [Certificates & Cryptography](#9-certificates--cryptography)
10. [Environment Variables & Sensitive Config](#10-environment-variables--sensitive-config)
11. [Startup Items & Autoruns](#11-startup-items--autoruns)
12. [File Integrity & Suspicious Files](#12-file-integrity--suspicious-files)
13. [Firewall & Security Controls](#13-firewall--security-controls)
14. [Browser & Credential Stores](#14-browser--credential-stores)

---

## 1. OS Version Vulnerabilities

**Scenario:** A CVE is published affecting a specific OS version (e.g. Windows Server 2019 < patch KB5005030, or Ubuntu 20.04 < 5.4.0-80). You need to identify which machines are running the affected version.

### Windows
```sql
-- Full OS version detail
SELECT name, version, major, minor, patch, build, platform, arch
FROM os_version;

-- Check Windows build number to map to patch level
SELECT name, version, build
FROM os_version
WHERE platform = 'windows';
```

### Linux
```sql
-- OS version and codename
SELECT name, version, major, minor, patch, codename, platform, arch
FROM os_version;

-- Cross-reference with platform for distro-specific CVEs
SELECT name, version, platform, platform_like, codename
FROM os_version
WHERE platform IN ('ubuntu', 'debian', 'rhel', 'centos', 'fedora');
```

### Notes
- On Windows, map `build` numbers to KB patch levels using Microsoft's update catalogue.
- On Linux, cross-reference `version` and `codename` against the CVE's affected range (e.g. USN advisories on Ubuntu).

---

## 2. Installed Software & Packages

**Scenario:** A CVE affects a specific application or library version (e.g. Log4Shell affecting log4j 2.x, or OpenSSL < 3.0.7). You need to find all machines with the vulnerable version installed.

### Windows — Registry-based programs
```sql
-- All installed programs (includes version)
SELECT name, version, install_location, publisher, install_date
FROM programs
ORDER BY name;

-- Search for a specific application
SELECT name, version, install_location, publisher
FROM programs
WHERE name LIKE '%openssl%'
   OR name LIKE '%log4j%'
   OR name LIKE '%apache%';
```

### Windows — Additional packages via chocolatey / npm globals
```sql
-- Chocolatey packages
SELECT name, version, path
FROM chocolatey_packages;

-- npm globally installed packages
SELECT name, version, path
FROM npm_packages
WHERE path LIKE 'C:\Users\%\AppData\Roaming\npm\%'
   OR path LIKE 'C:\Program Files\nodejs\%';
```

### Linux — System packages
```sql
-- Debian/Ubuntu (dpkg-based)
SELECT name, version, arch, status
FROM deb_packages
WHERE status = 'install ok installed'
ORDER BY name;

-- Search for specific package
SELECT name, version, arch
FROM deb_packages
WHERE name LIKE '%openssl%'
   OR name LIKE '%libssl%'
   OR name LIKE '%curl%';

-- RPM-based (RHEL, CentOS, Fedora)
SELECT name, version, release, arch, install_time
FROM rpm_packages
ORDER BY name;

-- Search RPM
SELECT name, version, release
FROM rpm_packages
WHERE name LIKE '%openssl%'
   OR name LIKE '%log4j%';
```

### Linux — Python packages
```sql
-- System-wide Python packages
SELECT name, version, path
FROM python_packages;

-- Search for vulnerable Python library
SELECT name, version, path
FROM python_packages
WHERE name LIKE '%requests%'
   OR name LIKE '%urllib%'
   OR name LIKE '%cryptography%';
```

### Cross-platform — Find files matching library names
```sql
-- Locate log4j JAR files anywhere on disk (Linux)
SELECT path, filename, size, mtime
FROM file
WHERE path LIKE '/opt/%'
   OR path LIKE '/var/%'
   OR path LIKE '/usr/%'
AND filename LIKE 'log4j%';

-- Locate DLL files for a specific library (Windows)
SELECT path, filename, size
FROM file
WHERE path LIKE 'C:\Program Files\%'
AND filename LIKE 'libssl%';
```

---

## 3. Running Processes & Services

**Scenario:** A CVE affects a running service or daemon (e.g. Apache httpd, OpenSSH, or a vulnerable version of nginx). You need to identify if the service is actively running and what version it is.

### Windows — Services
```sql
-- All running services with path to binary
SELECT name, display_name, status, start_type, path
FROM services
WHERE status = 'RUNNING';

-- Search for specific service
SELECT name, display_name, status, path, user_account
FROM services
WHERE name LIKE '%apache%'
   OR name LIKE '%nginx%'
   OR name LIKE '%ssh%'
   OR name LIKE '%iis%'
   OR name LIKE '%w3svc%';

-- Services running as SYSTEM (high privilege)
SELECT name, display_name, status, path, user_account
FROM services
WHERE user_account = 'LocalSystem'
AND status = 'RUNNING';
```

### Cross-platform — Running processes
```sql
-- All running processes with path and user
SELECT pid, name, path, cmdline, uid, start_time
FROM processes
ORDER BY name;

-- Find specific process
SELECT pid, name, path, cmdline, uid
FROM processes
WHERE name LIKE '%apache%'
   OR name LIKE '%nginx%'
   OR name LIKE '%sshd%'
   OR name LIKE '%httpd%'
   OR name LIKE '%java%';

-- Processes running as root/SYSTEM
SELECT pid, name, path, cmdline
FROM processes
WHERE uid = 0;  -- Linux root

-- Processes with no on-disk binary (potential hollow process)
SELECT pid, name, path, cmdline
FROM processes
WHERE path = ''
   OR path IS NULL;

-- Process listening sockets (cross-reference network exposure)
SELECT p.pid, p.name, p.path, l.address, l.port, l.protocol
FROM processes p
JOIN listening_ports l ON p.pid = l.pid
ORDER BY l.port;
```

### Linux — Systemd services
```sql
-- All systemd units and their state
SELECT id, description, load_state, active_state, sub_state, fragment_path
FROM systemd_units
WHERE active_state = 'active';

-- Find specific service unit
SELECT id, active_state, sub_state, fragment_path
FROM systemd_units
WHERE id LIKE '%apache%'
   OR id LIKE '%nginx%'
   OR id LIKE '%ssh%';
```

---

## 4. Network Exposure

**Scenario:** A CVE requires a service to be network-accessible (e.g. EternalBlue requires SMB on port 445 to be exposed). You need to identify what ports are open and which processes are behind them.

### Listening ports (all platforms)
```sql
-- All listening ports with owning process
SELECT l.address, l.port, l.protocol, l.fd, p.pid, p.name, p.path
FROM listening_ports l
LEFT JOIN processes p ON l.pid = p.pid
ORDER BY l.port;

-- Listening on all interfaces (0.0.0.0 or ::) — externally reachable
SELECT l.port, l.protocol, p.name, p.path, p.cmdline
FROM listening_ports l
LEFT JOIN processes p ON l.pid = p.pid
WHERE l.address = '0.0.0.0'
   OR l.address = '::'
ORDER BY l.port;

-- High-risk ports
SELECT l.address, l.port, l.protocol, p.name, p.cmdline
FROM listening_ports l
LEFT JOIN processes p ON l.pid = p.pid
WHERE l.port IN (21, 22, 23, 25, 53, 80, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017);
```

### Active network connections
```sql
-- All active connections
SELECT pid, family, protocol, local_address, local_port,
       remote_address, remote_port, state
FROM process_open_sockets
WHERE state = 'ESTABLISHED'
ORDER BY remote_address;

-- Outbound connections to uncommon ports
SELECT p.name, s.local_address, s.local_port,
       s.remote_address, s.remote_port, s.state
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
WHERE s.state = 'ESTABLISHED'
AND s.remote_port NOT IN (80, 443, 53);

-- DNS lookups being made (identify C2 candidates)
SELECT p.name, s.remote_address, s.remote_port
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
WHERE s.remote_port = 53;
```

### Windows — Shared resources and SMB exposure
```sql
-- Shared folders (SMB attack surface)
SELECT name, path, description, type
FROM shared_resources;
```

---

## 5. User & Privilege Escalation Risks

**Scenario:** A CVE enables privilege escalation (e.g. Dirty Pipe on Linux, PrintNightmare on Windows). You need to assess the user/group landscape and identify risky privilege configurations.

### Windows — Users and groups
```sql
-- Local user accounts
SELECT uid, gid, username, description, directory, is_hidden
FROM users;

-- Members of local Administrators group
SELECT u.username, u.uid, u.description
FROM users u
JOIN user_groups ug ON u.uid = ug.uid
WHERE ug.gid = (
  SELECT gid FROM groups WHERE groupname = 'Administrators'
);

-- All groups
SELECT gid, groupname
FROM groups
ORDER BY groupname;
```

### Linux — Users, groups, sudo
```sql
-- All user accounts
SELECT uid, gid, username, description, directory, shell
FROM users
ORDER BY uid;

-- Privileged accounts (UID 0)
SELECT uid, username, shell, directory
FROM users
WHERE uid = 0;

-- Accounts with login shells (potential interactive access)
SELECT username, uid, shell, directory
FROM users
WHERE shell NOT IN ('/bin/false', '/usr/sbin/nologin', '/sbin/nologin');

-- Sudoers entries
SELECT header, rule_details
FROM sudoers;

-- SUID/SGID binaries (privilege escalation candidates)
SELECT path, filename, permissions, uid, gid, mtime
FROM file
WHERE (permissions LIKE '%s%')
AND path LIKE '/usr/%'
OR path LIKE '/bin/%'
OR path LIKE '/sbin/%';

-- World-writable files in sensitive paths
SELECT path, filename, permissions
FROM file
WHERE permissions LIKE '%7'
AND (path LIKE '/etc/%' OR path LIKE '/usr/bin/%');
```

### Cross-platform — Logged in users
```sql
-- Currently logged in users
SELECT type, user, host, time, tty
FROM logged_in_users;

-- Login history
SELECT username, tty, host, time, type
FROM last;
```

---

## 6. Kernel & Drivers

**Scenario:** A CVE targets a specific kernel version or a vulnerable driver (e.g. a Linux kernel < 5.16.11 is affected by a local privilege escalation, or a Windows driver has a known exploit). You need to identify the kernel version and loaded modules.

### Linux — Kernel info
```sql
-- Kernel version
SELECT version, arguments, path, device
FROM kernel_info;

-- Loaded kernel modules
SELECT name, size, status, address
FROM kernel_modules
ORDER BY name;

-- Search for specific module
SELECT name, size, status, address
FROM kernel_modules
WHERE name LIKE '%netfilter%'
   OR name LIKE '%nfs%'
   OR name LIKE '%kvm%';
```

### Windows — Drivers
```sql
-- All loaded drivers
SELECT device_name, device_type, image, description, inf, manufacturer
FROM drivers
ORDER BY device_name;

-- Unsigned or suspicious drivers
SELECT device_name, image, description, manufacturer
FROM drivers
WHERE manufacturer = ''
   OR manufacturer IS NULL;
```

### Cross-platform — System info
```sql
-- Hardware and OS summary
SELECT computer_name, hostname, cpu_type, cpu_brand,
       physical_memory, hardware_vendor, hardware_model,
       hardware_serial
FROM system_info;

-- CPU features (useful for Spectre/Meltdown validation)
SELECT feature, value
FROM cpuid;
```

---

## 7. Scheduled Tasks & Persistence

**Scenario:** A CVE or malware campaign establishes persistence via scheduled tasks, cron jobs, or startup entries. You need to enumerate all persistence mechanisms.

### Windows — Scheduled tasks
```sql
-- All scheduled tasks
SELECT name, action, path, enabled, run_on_load,
       last_run_time, next_run_time
FROM scheduled_tasks
ORDER BY name;

-- Enabled tasks only
SELECT name, action, path, run_on_load, last_run_time
FROM scheduled_tasks
WHERE enabled = 1;

-- Tasks running from suspicious paths
SELECT name, action, path
FROM scheduled_tasks
WHERE action LIKE '%AppData%'
   OR action LIKE '%Temp%'
   OR action LIKE '%ProgramData%'
   OR action LIKE '%powershell%'
   OR action LIKE '%cmd.exe%'
   OR action LIKE '%wscript%'
   OR action LIKE '%cscript%';
```

### Linux — Cron jobs
```sql
-- System-wide crontab
SELECT event, minute, hour, day_of_month, month, day_of_week, command, path
FROM crontab
ORDER BY path;

-- Per-user cron entries
SELECT event, command, path
FROM crontab
WHERE path LIKE '/var/spool/cron/%';
```

### Linux — Init and startup scripts
```sql
-- Startup items
SELECT name, path, args, type, source, status, start_interval
FROM startup_items;

-- Launch daemons / launch agents (also applies to macOS)
SELECT name, path, program_arguments, run_at_load, keep_alive
FROM launchd
WHERE run_at_load = 1;
```

---

## 8. IIS Web Server & Application Components

**Scenario:** A CVE affects IIS itself or a web application running on IIS (e.g. a vulnerable ASP.NET version, a specific handler, or an exposed module). You need to gather intelligence on what IIS is running and what components are loaded.

### IIS site configuration
```sql
-- All IIS websites
SELECT name, id, path, enabled, physical_path,
       bindings, app_pool
FROM iis_sites;

-- Enabled sites only
SELECT name, physical_path, bindings, app_pool
FROM iis_sites
WHERE enabled = 1;
```

### IIS application pools
```sql
-- Application pools (identify .NET CLR versions)
SELECT name, clr_version, enable32_bit, managed_pipeline_mode,
       state, user_name
FROM iis_app_pools;

-- App pools running with custom identity (not ApplicationPoolIdentity)
SELECT name, clr_version, user_name, state
FROM iis_app_pools
WHERE user_name NOT LIKE '%ApplicationPoolIdentity%'
AND user_name NOT LIKE '%NetworkService%'
AND user_name NOT LIKE '%LocalSystem%';
```

### ASP.NET and .NET Framework version detection
```sql
-- Detect installed .NET Framework versions via registry
SELECT path, name, data
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\%'
AND name = 'Version';

-- .NET Core / .NET 5+ installs
SELECT path, name, data
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\dotnet\Setup\InstalledVersions\%';
```

### IIS modules and handlers (via registry)
```sql
-- IIS installed components
SELECT path, name, data
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\InetStp\Components\%';
```

### Web application files — scanning for vulnerable components
```sql
-- Find web.config files (may reveal framework versions, connection strings)
SELECT path, filename, size, mtime
FROM file
WHERE filename = 'web.config'
AND path LIKE 'C:\inetpub\%';

-- Find DLLs in IIS app directories (identify libraries deployed in apps)
SELECT path, filename, size, mtime
FROM file
WHERE path LIKE 'C:\inetpub\%'
AND filename LIKE '%.dll';

-- Find JAR files (Java apps hosted behind IIS reverse proxy)
SELECT path, filename, size, mtime
FROM file
WHERE path LIKE 'C:\inetpub\%'
AND filename LIKE '%.jar';

-- Find packages.config or project.json (NuGet dependency files)
SELECT path, filename, mtime
FROM file
WHERE filename IN ('packages.config', 'project.json', 'packages.lock.json')
AND path LIKE 'C:\inetpub\%';
```

### IIS running processes
```sql
-- IIS worker processes (w3wp.exe) and their app pools
SELECT pid, name, path, cmdline, uid
FROM processes
WHERE name = 'w3wp.exe';

-- IIS service status
SELECT name, display_name, status, start_type, path
FROM services
WHERE name IN ('W3SVC', 'WAS', 'IISADMIN');
```

---

## 9. Certificates & Cryptography

**Scenario:** A CVE affects a specific TLS version, cipher suite, or certificate (e.g. weak certificate, expired cert, or use of deprecated TLS 1.0/1.1).

### Windows — Certificate store
```sql
-- All certificates in the Windows certificate store
SELECT subject, issuer, not_valid_before, not_valid_after,
       key_algorithm, key_strength, signing_algorithm, path
FROM certificates
ORDER BY not_valid_after;

-- Expired certificates
SELECT subject, issuer, not_valid_after, path
FROM certificates
WHERE not_valid_after < strftime('%s', 'now');

-- Weak key strength (< 2048 bit RSA is considered weak)
SELECT subject, issuer, key_strength, key_algorithm, path
FROM certificates
WHERE CAST(key_strength AS INTEGER) < 2048
AND key_algorithm = 'RSA';

-- Self-signed certificates (issuer = subject)
SELECT subject, issuer, not_valid_after, path
FROM certificates
WHERE subject = issuer;
```

### Linux — Certificate files on disk
```sql
-- Find certificate files
SELECT path, filename, mtime
FROM file
WHERE (filename LIKE '%.pem' OR filename LIKE '%.crt' OR filename LIKE '%.cer')
AND (path LIKE '/etc/ssl/%' OR path LIKE '/usr/local/share/ca-certificates/%');
```

---

## 10. Environment Variables & Sensitive Config

**Scenario:** A CVE or misconfiguration exposes sensitive data via environment variables (e.g. credentials, API keys, or connection strings set in environment).

### Cross-platform — Environment variables
```sql
-- All environment variables for running processes
SELECT pid, key, value
FROM process_envs
ORDER BY key;

-- Find processes with suspicious env vars
SELECT p.name, e.key, e.value
FROM process_envs e
JOIN processes p ON e.pid = p.pid
WHERE e.key LIKE '%PASSWORD%'
   OR e.key LIKE '%SECRET%'
   OR e.key LIKE '%API_KEY%'
   OR e.key LIKE '%TOKEN%'
   OR e.key LIKE '%CREDENTIAL%';

-- PATH manipulation (potential hijacking)
SELECT p.name, e.value
FROM process_envs e
JOIN processes p ON e.pid = p.pid
WHERE e.key = 'PATH'
AND (e.value LIKE '%.%' OR e.value LIKE '%tmp%');
```

---

## 11. Startup Items & Autoruns

**Scenario:** Malware or a vulnerable application establishes persistence in startup locations. You need to audit all autorun mechanisms.

### Windows — Registry run keys
```sql
-- HKCU and HKLM run keys
SELECT path, name, data
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run%'
   OR path LIKE 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run%';

-- Winlogon entries (common persistence location)
SELECT path, name, data
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon%';

-- Browser helper objects (BHOs)
SELECT path, name, data
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\%';
```

### Cross-platform — Startup items table
```sql
SELECT name, path, args, type, source, status
FROM startup_items
ORDER BY type;
```

---

## 12. File Integrity & Suspicious Files

**Scenario:** A CVE results in malicious file drops, or you need to verify that critical system binaries have not been tampered with.

### Cross-platform — File hashing
```sql
-- Hash a specific critical file
SELECT path, md5, sha1, sha256
FROM hash
WHERE path = '/usr/bin/sudo';   -- Linux

-- Windows equivalent
SELECT path, md5, sha1, sha256
FROM hash
WHERE path = 'C:\Windows\System32\cmd.exe';

-- Hash all files in a suspicious directory
SELECT path, filename, md5, sha256
FROM hash
WHERE directory = '/tmp';

-- Recently modified files in sensitive locations (Linux)
SELECT path, filename, mtime, permissions, uid
FROM file
WHERE path LIKE '/etc/%'
AND mtime > (strftime('%s', 'now') - 86400);  -- Modified in last 24h

-- Recently modified system files (Windows)
SELECT path, filename, mtime
FROM file
WHERE path LIKE 'C:\Windows\System32\%'
AND mtime > (strftime('%s', 'now') - 86400);
```

---

## 13. Firewall & Security Controls

**Scenario:** Validate that host-based firewall is active and correctly configured, and that security tools are running.

### Windows — Firewall
```sql
-- Windows Firewall rules
SELECT name, action, enabled, direction, protocol,
       local_addresses, remote_addresses, local_ports, remote_ports
FROM windows_firewall_rules
WHERE enabled = 1
ORDER BY direction;

-- Inbound allow rules (attack surface)
SELECT name, action, local_ports, remote_addresses
FROM windows_firewall_rules
WHERE enabled = 1
AND action = 'Allow'
AND direction = 'In';
```

### Linux — iptables
```sql
-- iptables rules
SELECT filter_name, chain, policy, target,
       match_extensions, target_extensions
FROM iptables
ORDER BY chain;
```

### Cross-platform — Security products (AV/EDR)
```sql
-- Windows Defender / security center products (Windows)
SELECT type, name, state, product_type
FROM windows_security_products;

-- Check if common security processes are running (cross-platform)
SELECT pid, name, path
FROM processes
WHERE name LIKE '%defender%'
   OR name LIKE '%sentinel%'
   OR name LIKE '%crowdstrike%'
   OR name LIKE '%cylance%'
   OR name LIKE '%carbonblack%'
   OR name LIKE '%falcond%';
```

---

## 14. Browser & Credential Stores

**Scenario:** A CVE or post-compromise assessment requires understanding what credentials or browser data may be accessible on the machine.

### Cross-platform — Browser plugins and extensions
```sql
-- Chrome extensions
SELECT uid, name, identifier, version, description, default_locale, path
FROM chrome_extensions;

-- Firefox addons
SELECT uid, name, identifier, version, description, path
FROM firefox_addons;

-- Internet Explorer browser helper objects (Windows)
SELECT path, name, data
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\%';
```

### Windows — Credential-related
```sql
-- Keychain / credential manager entries
SELECT namespace, friendly_name, target_name, type, comment, username
FROM windows_credential_guard_devices;

-- Check for credential files
SELECT path, filename, mtime
FROM file
WHERE filename IN ('credentials', 'id_rsa', 'id_ed25519', '.netrc', 'passwd')
AND (path LIKE 'C:\Users\%' OR path LIKE '/home/%' OR path LIKE '/root/%');
```

### Linux — SSH keys and credentials
```sql
-- SSH authorized keys
SELECT path, filename, mtime
FROM file
WHERE filename = 'authorized_keys'
AND path LIKE '/home/%/.ssh/%';

-- Private key files
SELECT path, filename, permissions, mtime
FROM file
WHERE (filename LIKE 'id_rsa%' OR filename LIKE 'id_ed25519%' OR filename LIKE '*.pem')
AND (path LIKE '/home/%/.ssh/%' OR path LIKE '/root/.ssh/%');
```

---

## Quick Reference — Platform Table Coverage

| Table | Windows | Linux | Notes |
|---|---|---|---|
| `os_version` | ✅ | ✅ | Core OS fingerprinting |
| `programs` | ✅ | ❌ | Windows installed software |
| `deb_packages` | ❌ | ✅ | Debian/Ubuntu only |
| `rpm_packages` | ❌ | ✅ | RHEL/CentOS/Fedora only |
| `processes` | ✅ | ✅ | Running process list |
| `services` | ✅ | ✅ | Windows services / init |
| `listening_ports` | ✅ | ✅ | Open ports |
| `process_open_sockets` | ✅ | ✅ | Active connections |
| `users` | ✅ | ✅ | Local user accounts |
| `sudoers` | ❌ | ✅ | Linux sudo config |
| `kernel_info` | ❌ | ✅ | Linux kernel version |
| `kernel_modules` | ❌ | ✅ | Loaded kernel modules |
| `drivers` | ✅ | ❌ | Windows drivers |
| `scheduled_tasks` | ✅ | ❌ | Windows task scheduler |
| `crontab` | ❌ | ✅ | Linux cron jobs |
| `registry` | ✅ | ❌ | Windows registry |
| `certificates` | ✅ | ❌ | Windows cert store |
| `iis_sites` | ✅ | ❌ | IIS websites |
| `iis_app_pools` | ✅ | ❌ | IIS app pools |
| `hash` | ✅ | ✅ | File hashing |
| `windows_firewall_rules` | ✅ | ❌ | Host firewall |
| `iptables` | ❌ | ✅ | Linux firewall rules |
| `chrome_extensions` | ✅ | ✅ | Browser extensions |
| `python_packages` | ✅ | ✅ | Python pip packages |
| `npm_packages` | ✅ | ✅ | Node.js packages |
| `systemd_units` | ❌ | ✅ | Systemd service state |

---

*Generated for security infrastructure mapping and CVE validation using OSQuery.*
*Always run queries with appropriate privileges — some tables (e.g. process_open_sockets, kernel_modules) require root/SYSTEM.*
