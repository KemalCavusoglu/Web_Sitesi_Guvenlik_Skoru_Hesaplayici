#!/usr/bin/env python3
"""
Web Güvenlik Skorlayıcı MCP Server
"""

import asyncio
import json
import sys
import os
import subprocess
import requests
import socket
import dns.resolver
from typing import Any, Sequence
from urllib.parse import urlparse
import time

from mcp import ClientSession
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    TextContent,
    Tool,
)

# .env dosyasını yükle
from dotenv import load_dotenv
load_dotenv()

# API anahtarı .env dosyasından yükleniyor
# Not: API anahtarının olmadığı durumlar için kod içinde kontrol mekanizması var

# Wrapper fonksiyonlar - FastMCP import sorununu çözmek için

def nikto_scan_wrapper(target_url: str) -> str:
    """Nikto tarama wrapper"""
    try:
        project_root = os.path.dirname(os.path.abspath(__file__))
        nikto_path = os.path.join(project_root, "nikto-master", "program", "nikto.pl")
        
        if not os.path.exists(nikto_path):
            return f"[-] nikto.pl dosyası bulunamadı: {nikto_path}"

        is_ssl = target_url.startswith("https://")
        output_path = os.path.join(project_root, "output", "nikto_sonuc.txt")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        if os.path.exists(output_path):
            os.remove(output_path)

        komut = [
            "perl", nikto_path,
            "-h", target_url,
            "-Plugins", "nikto_headers,nikto_sitefiles",
            "-no404", "-nolookup",
            "-timeout", "10",
            "-maxtime", "300",
            "-Display", "V",
            "-Format", "txt",
            "-o", output_path
        ]
        if is_ssl:
            komut.insert(4, "-ssl")

        result = subprocess.run(komut, capture_output=True, text=True, timeout=300, cwd=project_root)
        stderr = result.stderr.strip()

        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result.stdout)

        if os.path.getsize(output_path) > 0:
            with open(output_path, "r", encoding="utf-8") as f:
                nikto_output = f.read()
            return f"[+] Nikto hızlı taraması tamamlandı.\nNikto stderr: {stderr}\n\nNikto Sonuçları:\n{nikto_output}"
        else:
            return f"[-] Nikto çıktı dosyası hala boş. Tarama başarısız.\nNikto stderr: {stderr}"

    except subprocess.TimeoutExpired:
        return f"[-] Nikto taraması 5 dakika içinde tamamlanamadı (timeout)."
    except FileNotFoundError as e:
        return f"[-] Perl veya Nikto bulunamadı. Perl kurulu mu? Hata: {e}"
    except Exception as e:
        return f"[-] run_nikto_scan hatası: {e}"

def nmap_scan_wrapper(target_url: str) -> str:
    """Nmap tarama wrapper"""
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname if parsed.hostname else target_url

        project_root = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(project_root, "output")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "nmap_sonuc.txt")

        nmap_path = os.path.join(project_root, "Nmap", "nmap.exe")
        
        if not os.path.exists(nmap_path):
            return f"[-] Nmap bulunamadı: {nmap_path}"

        komut = [
            nmap_path,
            "-Pn",
            "-sV",
            "-p", "443,80",
            "--script", "vulners,ssl-heartbleed,ssl-poodle,ssl-enum-ciphers,ssl-dh-params",
            hostname
        ]
        result = subprocess.run(komut, capture_output=True, text=True, cwd=project_root)

        if result.stdout:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            return f"[+] Nmap zafiyet taraması tamamlandı ve sonuçlar aşağıdadır:\n\n{result.stdout}"
        else:
            return f"[-] Nmap çıktı üretmedi:\n{result.stderr}"

    except FileNotFoundError as e:
        return f"[-] Nmap executable bulunamadı. Hata: {e}"
    except Exception as e:
        return f"[-] Nmap tarama hatası: {e}"

def abuseipdb_scan_wrapper(url: str, api_key: str) -> str:
    """AbuseIPDB tarama wrapper"""
    def get_ip_from_url(url):
        try:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            parsed = urlparse(url)
            return socket.gethostbyname(parsed.hostname)
        except Exception as e:
            return f"[!] IP çözümlenemedi: {e}"

    def check_abuseipdb(ip, api_key):
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                return response.json()["data"]
            elif response.status_code == 401:
                return {"error": "API_AUTH_FAILED", "message": "API anahtarı geçersiz veya eksik"}
            else:
                return f"[!] API hatası: {response.status_code}\n[!] Dönen içerik: {response.text}"
        except Exception as e:
            return f"[!] API çağrısı başarısız: {e}"

    project_root = os.path.dirname(os.path.abspath(__file__))
    
    # API anahtarı kontrolü
    if not api_key or api_key == "your_abuseipdb_api_key_here" or len(api_key) < 10:
        rapor = """[!] AbuseIPDB API Anahtarı Sorunu

❌ API anahtarı eksik, geçersiz veya henüz ayarlanmamış.

📋 Çözüm Adımları:
1. https://www.abuseipdb.com/api adresine gidin
2. Ücretsiz hesap oluşturun
3. API anahtarınızı alın  
4. .env dosyasında ABUSEIPDB_API_KEY=your_actual_key şeklinde ayarlayın

⚠️  Bu tarama atlandı - API anahtarı olmadan AbuseIPDB sorgusu yapılamaz.
"""
        output_dir = os.path.join(project_root, "output")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "abuseipdb_sonuc.txt")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rapor)
        return rapor

    ip = get_ip_from_url(url)
    if not ip or (isinstance(ip, str) and ip.startswith("[!]")):
        rapor = f"[!] IP çözümlenemedi, işlem iptal edildi.\n{ip}"
        output_dir = os.path.join(project_root, "output")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "abuseipdb_sonuc.txt")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rapor)
        return rapor

    data = check_abuseipdb(ip, api_key)
    
    # API hatası kontrolü
    if isinstance(data, dict) and data.get("error") == "API_AUTH_FAILED":
        rapor = f"""[!] AbuseIPDB API Kimlik Doğrulama Hatası - IP: {ip}

❌ API anahtarı reddedildi. Sebep: {data.get('message', 'Bilinmeyen hata')}

📋 Çözüm Önerileri:
1. API anahtarınızın doğru olduğundan emin olun
2. API v2 anahtarı kullandığınızdan emin olun (v1 anahtarı artık çalışmaz)
3. API anahtarının aktif ve iptal edilmemiş olduğunu kontrol edin
4. Aylık sorgu limitinizi aşmadığınızdan emin olun

💡 Test için geçici olarak bu tarama atlandı.
"""
        output_dir = os.path.join(project_root, "output")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "abuseipdb_sonuc.txt")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rapor)
        return rapor
        
    if not isinstance(data, dict):
        rapor = f"[!] API'den veri alınamadı.\n{data}"
        output_dir = os.path.join(project_root, "output")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "abuseipdb_sonuc.txt")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rapor)
        return rapor

    reports = data.get("reports", [])

    has_malware = any(5 in r.get("categories", []) for r in reports)
    has_phishing = any(6 in r.get("categories", []) for r in reports)
    has_botnet = any(14 in r.get("categories", []) for r in reports)
    has_bruteforce = any(18 in r.get("categories", []) for r in reports)
    has_scan = any(3 in r.get("categories", []) for r in reports)

    rapor = f"""[+] AbuseIPDB Raporu - IP: {ip}
    - Abuse Score: {data['abuseConfidenceScore']}
    - Toplam Rapor: {data['totalReports']}
    - Ülke: {data.get('countryCode', 'Bilinmiyor')}
    - Son Rapor: {data.get('lastReportedAt', 'Yok')}
    - Malware geçmişi: {('❌ Malware distribution activity reported in last 30 days' if has_malware else '✅ No malware distribution (30 days)')}
    - Phishing geçmişi: {('❌ Phishing activity reported in last 30 days' if has_phishing else '✅ No phishing activity (30 days)')}
    - Botnet etkinliği: {('❌ Botnet activity reported' if has_botnet else '✅ No reports of botnet activity (30/90 days)')}
    - Brute force saldırı: {('❌ Brute force login attempts detected' if has_bruteforce else '✅ No brute force login attempts (30 days)')}
    - İzinsiz tarama: {('❌ Unsolicited scanning activity reported' if has_scan else '✅ No unsolicited scanning (30 days)')}
    """
    
    output_dir = os.path.join(project_root, "output")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "abuseipdb_sonuc.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(rapor)
    
    return rapor

def tum_araclari_calistir_internal(hedef: str) -> str:
    """
    Verilen hedef için tüm güvenlik araçlarını çalıştırır ve genel raporu döndürür.
    """
    raporlar = []
    
    # API anahtarını kontrol et
    api_key = os.getenv("ABUSEIPDB_API_KEY") 
    if not api_key:
        api_key = "test_key"  # Hata mesajı görünmesi için

    try:
        abuseipdb_sonuc = abuseipdb_scan_wrapper(hedef, api_key)
        raporlar.append("🔍 AbuseIPDB IP Güvenlik Kontrolü:\n" + str(abuseipdb_sonuc))
    except Exception as e:
        raporlar.append(f"❌ AbuseIPDB Hatası: {e}")

    try:
        nmap_sonuc = nmap_scan_wrapper(hedef)
        raporlar.append("🎯 Nmap Port ve Zafiyet Taraması:\n" + str(nmap_sonuc))
    except Exception as e:
        raporlar.append(f"❌ Nmap Hatası: {e}")

    try:
        nikto_sonuc = nikto_scan_wrapper(hedef)
        raporlar.append("🌐 Nikto Web Güvenlik Taraması:\n" + str(nikto_sonuc))
    except Exception as e:
        raporlar.append(f"❌ Nikto Hatası: {e}")

    # Sonuç özeti
    basarili_tarama = sum(1 for r in raporlar if not r.startswith("❌"))
    toplam_tarama = len(raporlar)
    
    # URL'den site adını çıkar
    from urllib.parse import urlparse
    parsed_url = urlparse(hedef)
    site_adi = parsed_url.netloc.upper() if parsed_url.netloc else hedef.upper()
    
    ozet = f"""
{'='*60}
📊 {site_adi} GÜVENLİK TARAMASI ÖZETİ
{'='*60}
✅ Başarılı Tarama: {basarili_tarama}/{toplam_tarama}
🎯 Hedef: {hedef}
📅 Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}
"""
    
    return ozet + "\n\n" + "\n\n".join(raporlar)

# MCP Server oluştur
server = Server("web-sitesi-guvenlik-skoru")

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """Mevcut araçları listele"""
    return [
        Tool(
            name="tum_araclari_calistir",
            description="Verilen hedef için tüm güvenlik araçlarını çalıştırır ve genel raporu döndürür.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hedef": {
                        "type": "string",
                        "description": "Taranacak hedef URL"
                    }
                },
                "required": ["hedef"]
            }
        ),
        Tool(
            name="nikto_scan",
            description="Nikto ile web güvenlik taraması yapar",
            inputSchema={
                "type": "object", 
                "properties": {
                    "target_url": {"type": "string", "description": "Hedef URL"}
                },
                "required": ["target_url"]
            }
        ),
        Tool(
            name="nmap_scan",
            description="Nmap ile port ve servis taraması yapar",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Hedef URL"}
                },
                "required": ["target_url"]
            }
        ),
        Tool(
            name="abuseipdb_scan",
            description="AbuseIPDB ile IP güvenlik kontrolü yapar",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Hedef URL"},
                    "api_key": {"type": "string", "description": "AbuseIPDB API anahtarı"}
                },
                "required": ["url", "api_key"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Araç çağrılarını işle"""
    try:
        if name == "tum_araclari_calistir":
            result = tum_araclari_calistir_internal(arguments["hedef"])
        elif name == "nikto_scan":
            result = nikto_scan_wrapper(arguments["target_url"])
        elif name == "nmap_scan":
            result = nmap_scan_wrapper(arguments["target_url"])
        elif name == "abuseipdb_scan":
            result = abuseipdb_scan_wrapper(arguments["url"], arguments["api_key"])
        else:
            result = f"Bilinmeyen araç: {name}"
        
        return [TextContent(type="text", text=str(result))]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Hata: {str(e)}")]

async def main_server():
    # Stdio üzerinden çalıştır
    async with mcp.server.stdio.stdio_server_session() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="web-sitesi-guvenlik-skoru",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main_server()) 