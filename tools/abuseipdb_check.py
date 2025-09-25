from mcp_instance import mcp
import requests
import socket
import os
from urllib.parse import urlparse

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
        else:
            return f"[!] API hatası: {response.status_code}\n[!] Dönen içerik: {response.text}"
    except Exception as e:
        return f"[!] API çağrısı başarısız: {e}"

@mcp.tool()
def abuseipdb_scan(url: str, api_key: str) -> str:
    """
    Verilen URL'nin IP adresini AbuseIPDB ile sorgular ve güvenlik raporunu döndürür.
    """
    ip = get_ip_from_url(url)
    if not ip or (isinstance(ip, str) and ip.startswith("[!]")):
        rapor = f"[!] IP çözümlenemedi, işlem iptal edildi.\n{ip}"
        # Dosyaya kaydet
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "abuseipdb_sonuc.txt")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rapor)
        return rapor

    data = check_abuseipdb(ip, api_key)
    if not isinstance(data, dict):
        rapor = f"[!] API'den veri alınamadı.\n{data}"
        # Dosyaya kaydet
        output_dir = "output"
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
    
    # Sonucu dosyaya kaydet
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "abuseipdb_sonuc.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(rapor)
    
    return rapor 