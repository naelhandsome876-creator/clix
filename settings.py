# -*- coding: utf-8 -*-
"""
config/settings.py
===================
Semua konstanta & konfigurasi global tool dikumpulkan di sini biar gampang
diubah tanpa harus utak-atik logic di modules/.
"""

import os

VERSION = "3.0.0"

# Folder root proyek (dua level di atas file ini: config/ -> root)
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_DIR = os.path.join(ROOT_DIR, "wordlists")

HEADERS_UA = {
    "User-Agent": "Mozilla/5.0 (Linux; Termux) CLIx/{} (Authorized-Pentest)".format(VERSION)
}

REQUEST_TIMEOUT_DEFAULT = 4

# Top port umum (mirip top-ports nmap, dipangkas biar ringan + cepat)
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1025, 1080, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095,
    2096, 3000, 3128, 3306, 3389, 3690, 4443, 4444, 4567, 5000, 5432, 5601,
    5900, 5985, 6379, 7001, 7002, 7070, 7443, 8000, 8008, 8080, 8081, 8088,
    8090, 8443, 8888, 9000, 9090, 9200, 9300, 9999, 10000, 11211, 27017,
    27018,
]

COMMON_SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle-DB",
    2049: "NFS", 3000: "Node/Dev-HTTP", 3128: "Proxy", 3306: "MySQL",
    3389: "RDP", 4443: "HTTPS-Alt", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

CMS_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "/wp-json/", "wp-emoji"],
    "Joomla": ["/administrator/", "Joomla!", "com_content"],
    "Drupal": ["Drupal.settings", "/sites/default/", "drupal.js"],
    "Magento": ["Mage.Cookies", "/skin/frontend/", "Magento"],
    "Laravel": ["laravel_session"],
    "Django": ["csrftoken"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "PrestaShop": ["PrestaShop", "prestashop"],
    "OpenCart": ["route=common", "OpenCart"],
    "CodeIgniter": ["ci_session"],
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

# Fingerprint WAF/CDN umum lewat header & cookie respons (deteksi pasif,
# tanpa payload aktif) — dipakai modules/waf_detect.py
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"server": "cloudflare", "cf-ray": None},
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": None, "server": "sucuri/cloudproxy"},
        "cookies": [],
    },
    "Akamai": {
        "headers": {"akamai-": None, "x-akamai-": None},
        "cookies": ["akamai"],
    },
    "Imperva/Incapsula": {
        "headers": {"x-iinfo": None, "x-cdn": "incapsula"},
        "cookies": ["incap_ses", "visid_incap"],
    },
    "AWS WAF/ELB": {
        "headers": {"x-amzn-requestid": None, "x-amz-cf-id": None},
        "cookies": ["awsalb", "awsalbcors"],
    },
    "F5 BIG-IP ASM": {
        "headers": {},
        "cookies": ["bigipserver", "ts01"],
    },
    "Fortinet FortiWeb": {
        "headers": {"fortiwafsid": None},
        "cookies": ["fortiwafsid"],
    },
    "Wordfence": {
        "headers": {"x-wf-": None},
        "cookies": [],
    },
}

ALL_MODULES = [
    "whois", "dns", "subdomain", "port", "ssl", "waf", "cms", "dir",
    "http_methods", "cookie", "cors", "takeover", "vuln",
]
