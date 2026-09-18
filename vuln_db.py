# -*- coding: utf-8 -*-
"""
config/vuln_db.py
==================
Database kerentanan OFFLINE berbasis versi software, dicocokkan ke banner
yang ditangkap modul port_scanner/cms_detect. Ini deteksi PASIF (cocokkan
angka versi ke daftar CVE publik yang sudah diketahui) — BUKAN exploitation
aktif. Tool tidak mengirim payload untuk membuktikan celah beneran bisa
dipakai; hasil di sini tetap wajib diverifikasi manual sebelum dilaporkan
ke client sebagai temuan final.

Format tiap entri:
    {
        "product": nama software yang dicari di banner (lowercase),
        "match": regex untuk ekstrak nomor versi dari banner,
        "affected_below": versi yang jadi batas rentan (string, dibandingkan
                           per-komponen angka), None kalau semua versi lama
                           tanpa perlu ekstraksi versi.
        "severity": "CRITICAL" | "HIGH" | "MEDIUM",
        "cve": id CVE (boleh lebih dari satu, dipisah koma),
        "title": ringkasan singkat,
    }

Database ini kecil & untuk contoh — silakan tambah entri sendiri sesuai
kebutuhan job (lihat CONTRIBUTING.md).
"""

import re


def _version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def version_lt(v1, v2):
    """True kalau v1 < v2, dibandingkan per-komponen angka."""
    t1, t2 = _version_tuple(v1), _version_tuple(v2)
    maxlen = max(len(t1), len(t2))
    t1 = t1 + (0,) * (maxlen - len(t1))
    t2 = t2 + (0,) * (maxlen - len(t2))
    return t1 < t2


VULN_DB = [
    {
        "product": "vsftpd 2.3.4",
        "match": None,
        "affected_below": None,
        "severity": "CRITICAL",
        "cve": "EDB-ID-49757 (backdoor command execution)",
        "title": "vsFTPd 2.3.4 mengandung backdoor yang sudah dikenal publik (RCE).",
    },
    {
        "product": "proftpd 1.3.3c",
        "match": None,
        "affected_below": None,
        "severity": "CRITICAL",
        "cve": "CVE-2010-4221",
        "title": "ProFTPD 1.3.3c mengandung backdoor pada source resmi yang dibajak.",
    },
    {
        "product": "openssh",
        "match": r"openssh[_\s]([\d.]+)",
        "affected_below": "7.4",
        "severity": "HIGH",
        "cve": "CVE-2016-10009, CVE-2016-10012, dkk",
        "title": "OpenSSH versi lama (<7.4) rentan beberapa CVE privilege escalation/agent forwarding.",
    },
    {
        "product": "apache",
        "match": r"apache[/\s]([\d.]+)",
        "affected_below": "2.4.49",
        "severity": "CRITICAL",
        "cve": "CVE-2021-41773, CVE-2021-42013",
        "title": "Apache HTTP Server 2.4.49/2.4.50 rentan path traversal & RCE.",
    },
    {
        "product": "nginx",
        "match": r"nginx[/\s]([\d.]+)",
        "affected_below": "1.20.1",
        "severity": "MEDIUM",
        "cve": "CVE-2021-23017",
        "title": "nginx versi lama berpotensi rentan resolver off-by-one heap write.",
    },
    {
        "product": "php",
        "match": r"php[/\s]([\d.]+)",
        "affected_below": "7.4",
        "severity": "MEDIUM",
        "cve": "Multiple (End-of-Life)",
        "title": "Versi PHP sudah End-of-Life, tidak dapat security patch resmi lagi.",
    },
    {
        "product": "exim",
        "match": r"exim[/\s]([\d.]+)",
        "affected_below": "4.92",
        "severity": "CRITICAL",
        "cve": "CVE-2019-10149",
        "title": "Exim < 4.92 rentan remote command execution ('Return of the WIZard').",
    },
    {
        "product": "samba",
        "match": r"samba[/\s]([\d.]+)",
        "affected_below": "4.6.4",
        "severity": "CRITICAL",
        "cve": "CVE-2017-7494",
        "title": "Samba < 4.6.4 rentan RCE lewat upload shared library (SambaCry).",
    },
    {
        "product": "mysql",
        "match": r"mysql[/\s]([\d.]+)",
        "affected_below": "5.7.0",
        "severity": "MEDIUM",
        "cve": "Multiple (End-of-Life risk)",
        "title": "Versi MySQL cukup lama, cek changelog untuk CVE spesifik versi ini.",
    },
    {
        "product": "wordpress",
        "match": r"wordpress[\s/]?([\d.]+)",
        "affected_below": "6.4.2",
        "severity": "HIGH",
        "cve": "Cek CVE spesifik versi di wpscan.com/vulnerabilities",
        "title": "Versi WordPress lama terekspos — banyak core/plugin CVE per versi, cek manual.",
    },
    {
        "product": "drupal",
        "match": r"drupal[\s/]?([\d.]+)",
        "affected_below": "7.58",
        "severity": "CRITICAL",
        "cve": "CVE-2018-7600 (Drupalgeddon2)",
        "title": "Drupal < 7.58 / < 8.5.1 rentan RCE tanpa autentikasi (Drupalgeddon2).",
    },
]
