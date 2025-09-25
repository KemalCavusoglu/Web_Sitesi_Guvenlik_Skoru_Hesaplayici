from mcp_instance import mcp
import os
import re
import dns.resolver
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

def whois_api_sorgusu(domain, api_key):
    try:
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
        response = requests.get(url, timeout=15)
        data = response.json()

        results = []
        results.append("[WHOIS - API]")
        
        whois_record = data.get("WhoisRecord", {})
        domain_name = whois_record.get("domainName", "Yok")
        expiration_date = whois_record.get("expiresDate", "Yok")
        status = whois_record.get("status", "Yok")

        results.append(f"Domain Name: {domain_name}")
        results.append(f"Expiration Date: {expiration_date}")
        results.append(f"Status: {status}")
        return results

    except Exception as e:
        return [f"[WHOIS - API] Hata: {e}"]

@mcp.tool()
def dns_scan(domain: str, api_key: str = None) -> str:
    """
    Verilen domain için DNS ve WHOIS kontrollerini yapar, sonucu string olarak döndürür.
    """
    parsed_url = urlparse(domain)
    domain_name = parsed_url.hostname if parsed_url.hostname else parsed_url.path
    if domain_name.count('.') > 2:
        domain_name = '.'.join(domain_name.split('.')[-2:])  # Alt domain temizle

    results = []
    results.append(f"[*] Hedef domain: {domain_name}")

    # WHOIS API sorgusu
    results.append("[*] WHOIS API sorgusu başlatılıyor...")
    if not api_key:
        api_key = os.getenv("WHOIS_API_KEY")
    whois_sonuc = whois_api_sorgusu(domain_name, api_key)
    results.extend(whois_sonuc)

    results.append("\n[DNS CHECKS]")

    # CAA Kaydı kontrolü
    try:
        dns.resolver.resolve(domain_name, 'CAA')
        results.append("CAA record found.")
    except dns.resolver.NoAnswer:
        results.append("CAA record not found.")
    except dns.resolver.NXDOMAIN:
        results.append("Domain bulunamadi.")
    except dns.resolver.NoNameservers:
        results.append("DNS sunucularina erisilemedi.")
    except Exception as e:
        results.append(f"CAA lookup error: {e}")

    # DNSSEC kontrolü
    try:
        answers = dns.resolver.resolve(domain_name, 'DNSKEY')
        if answers:
            results.append("DNSSEC enabled.")
        else:
            results.append("DNSSEC not enabled.")
    except Exception:
        results.append("DNSSEC not enabled.")

    # MX kayıt kontrolü
    try:
        mx = dns.resolver.resolve(domain_name, 'MX')
        records = [r.exchange.to_text() for r in mx]
        results.append(f"MX records: {records}")
    except:
        results.append("No MX records found.")

    # Sonucu dosyaya kaydet
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "dns_sonuc.txt")
    
    final_result = "\n".join(results)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(final_result)

    return final_result 