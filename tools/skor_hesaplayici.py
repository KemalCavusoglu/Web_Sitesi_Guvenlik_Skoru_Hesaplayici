from mcp_instance import mcp
import os
import re
from datetime import datetime

@mcp.tool()
def hesapla_abuseipdb() -> str:
    """
    AbuseIPDB ciktisini okuyarak puan hesaplar ve aciklamali satirlar uretir.
    Cikti dosyasi: output/abuseipdb_sonuc.txt
    """
    dosya = "output/abuseipdb_sonuc.txt"
    puan_ceza = 0
    yorumlar = ["--- AbuseIPDB ---"]

    try:
        with open(dosya, "r", encoding="utf-8") as f:
            for line in f:
                if "Abuse Score" in line:
                    score = int(line.split(":")[1].strip())
                    if score > 25:
                        yorumlar.append("Abuse Score > 25 ❌ Kotuye kullanim orani yuksek.")
                        puan_ceza += 10
                    else:
                        yorumlar.append("Abuse Score dusuk ✅ Guvenli gorunuyor.")
                elif "Toplam Rapor" in line:
                    toplam = int(line.split(":")[1].strip())
                    if toplam > 5:
                        yorumlar.append("5'ten fazla kullanici tarafindan raporlanmis ❌")
                        puan_ceza += 5
                    else:
                        yorumlar.append("Az sayida raporlanmis ✅")
                elif "Malware distribution activity reported" in line:
                    yorumlar.append("Malware gecmisi var ❌")
                    puan_ceza += 10
                elif "Phishing activity reported" in line:
                    yorumlar.append("Phishing gecmisi var ❌")
                    puan_ceza += 10
                elif "Botnet activity reported" in line:
                    yorumlar.append("Botnet aktivitesi tespit edilmis ❌")
                    puan_ceza += 5
                elif "Brute force login attempts detected" in line:
                    yorumlar.append("Brute force saldirilari var ❌")
                    puan_ceza += 5
                elif "Unsolicited scanning activity reported" in line:
                    yorumlar.append("Izinsiz tarama gecmisi var ❌")
                    puan_ceza += 5
                elif "No malware distribution" in line:
                    yorumlar.append("Malware aktivitesi yok ✅")
                elif "No phishing activity" in line:
                    yorumlar.append("Phishing aktivitesi yok ✅")
                elif "No reports of botnet activity" in line:
                    yorumlar.append("Botnet gecmisi yok ✅")
                elif "No brute force login attempts" in line:
                    yorumlar.append("Brute force saldirisi yok ✅")
                elif "No unsolicited scanning" in line:
                    yorumlar.append("Tarama gecmisi yok ✅")

        puan = max(100 - puan_ceza, 0)
        yorumlar.append(f"AbuseIPDB Puani: {puan} / 100")

    except FileNotFoundError:
        yorumlar.append("❌ AbuseIPDB sonucu dosyasi bulunamadi. Puan hesaplanamadi.")
        puan = 0

    return "\n".join(yorumlar)


@mcp.tool()
def hesapla_email() -> str:
    """
    Email (SPF / DMARC) tarama sonucunu okuyarak puan hesaplar ve aciklamali satirlar dondurur.
    Cikti dosyasi: output/email_sonuc.txt
    """
    dosya = "output/email_sonuc.txt"
    puan = 60
    yorumlar = ["--- Email SPF / DMARC ---"]

    try:
        with open(dosya, encoding="utf-8") as f:
            satirlar = f.readlines()

        for satir in satirlar:
            yorumlar.append(satir.strip())

            if "\t✅\t" in satir:
                continue
            elif "p=none" in satir:
                yorumlar.append("DMARC politikasi p=none ❌ Koruma saglamaz.")
                puan -= 5
            else:
                yorumlar.append("❌ Email kaydi hatali veya eksik.")
                puan -= 10

        puan = max(puan, 0)
        yorumlar.append(f"Email Puanı: {puan} / 60")

    except FileNotFoundError:
        yorumlar.append("❌ email_sonuc.txt dosyasi bulunamadi. Puan hesaplanamadi.")
        puan = 0

    return "\n".join(yorumlar)


@mcp.tool()
def hesapla_dns() -> str:
    """
    dns_sonuc.txt dosyasini okuyarak WHOIS ve DNS skorlarini hesaplar.
    ✅ / ❌ seklinde yorumlu satirlar dondurur.
    """
    dosya = "output/dns_sonuc.txt"
    puan = 0
    whois_score = 0
    dns_score = 0
    yorumlar = ["--- DNS / WHOIS ---"]

    if not os.path.exists(dosya):
        yorumlar.append("❌ dns_sonuc.txt dosyasi bulunamadi.")
        return "\n".join(yorumlar)

    with open(dosya, "r", encoding="utf-8") as f:
        content = f.read()

    # WHOIS kontrolu
    if "[WHOIS - API]" in content:
        if re.search(r"Domain Name:\s*\S+", content, re.IGNORECASE):
            whois_score += 10
            yorumlar.append("✅ Domain adi mevcut.")
        else:
            yorumlar.append("❌ Domain adi eksik.")

        if re.search(r"Expiration Date:\s*\S+", content, re.IGNORECASE):
            yorumlar.append("✅ Domain suresi belirtilmis.")
            exp_match = re.search(r"Expiration Date:\s*(\S+)", content)
            if exp_match:
                try:
                    exp_date = datetime.strptime(exp_match.group(1).split("T")[0], "%Y-%m-%d")
                    kalan_gun = (exp_date - datetime.utcnow()).days
                    if kalan_gun > 30:
                        whois_score += 5
                        yorumlar.append("✅ Domain suresi yeterli (>30 gun).")
                    else:
                        yorumlar.append("❌ Domain suresi kisa.")
                except:
                    yorumlar.append("❌ Domain tarih formati gecersiz.")
        else:
            yorumlar.append("❌ Domain suresi bulunamadi.")

        if "inactive" in content.lower():
            whois_score -= 5
            yorumlar.append("❌ Domain durumu: inactive")
        if "pendingdelete" in content.lower():
            whois_score -= 5
            yorumlar.append("❌ Domain pending delete durumunda")
        if "pendingrestore" in content.lower():
            whois_score -= 5
            yorumlar.append("❌ Domain pending restore durumunda")

        if "clientDeleteProhibited" in content:
            whois_score += 3
            yorumlar.append("✅ Domain silme korumasi aktif.")
        if "clientTransferProhibited" in content:
            whois_score += 3
            yorumlar.append("✅ Domain transfer korumasi aktif.")
        if "clientUpdateProhibited" in content:
            whois_score += 3
            yorumlar.append("✅ Domain guncelleme korumasi aktif.")

        if "clientHold" not in content:
            whois_score += 3
            yorumlar.append("✅ clientHold durumu yok.")
        if "serverHold" not in content:
            whois_score += 3
            yorumlar.append("✅ serverHold durumu yok.")

        if "renewprohibited" not in content.lower():
            whois_score += 5
            yorumlar.append("✅ Yenileme kisiti yok.")
        else:
            whois_score -= 5
            yorumlar.append("❌ renewProhibited etiketi mevcut.")

    # DNS kontrolleri
    if "CAA record found." in content:
        dns_score += 10
        yorumlar.append("✅ CAA kaydi mevcut.")
    else:
        yorumlar.append("❌ CAA kaydi bulunamadi.")

    if "DNSSEC enabled." in content:
        dns_score += 10
        yorumlar.append("✅ DNSSEC aktif.")
    else:
        yorumlar.append("❌ DNSSEC aktif degil.")

    if "No MX records found." not in content:
        dns_score += 10
        yorumlar.append("✅ MX kayitlari mevcut.")
    else:
        yorumlar.append("❌ MX kayitlari bulunamadi.")

    if all(x in content for x in ["CAA record found.", "DNSSEC enabled.", "MX records"]):
        dns_score += 10
        yorumlar.append("✅ Tum DNS kontrolleri gecti (+10 bonus).")

    puan = whois_score + dns_score
    yorumlar.append(f"WHOIS Puani: {whois_score}/60")
    yorumlar.append(f"DNS Puani: {dns_score}/40")
    yorumlar.append(f"Toplam DNS/WHOIS Puani: {puan} / 100")

    return "\n".join(yorumlar)


@mcp.tool()
def hesapla_sslyze() -> str:
    """
    sslyze_sonuc.txt dosyasini okuyarak SSL/TLS guvenligi icin puan hesaplar.
    Tespit edilen zayifliklara gore aciklamali ✅/❌ satirlar olusturur.
    """
    dosya = "output/sslyze_sonuc.txt"
    puan = 100
    yorumlar = ["--- SSL/TLS Guvenligi (SSLyze) ---"]

    kriterler = {
        "HSTS": {"regex": r"strict-transport-security", "puan": 5},
        "SSL chain eksik": {"regex": r"certificate chain.*incomplete", "puan": 10},
        "Zayif sifreleme": {"regex": r"weak cipher|export cipher|LOW|NULL", "puan": 10},
        "Sertifika iptal edilmis": {"regex": r"revoked.*certificate", "puan": 10},
        "HTTP yonlendirme yok": {"regex": r"no redirect.*http.*https", "puan": 5},
        "Sertifika eslesme sorunu": {"regex": r"hostname.*does not match", "puan": 10},
        "Sertifika suresi gecmis": {"regex": r"certificate.*expired", "puan": 10},
        "Guvenilmeyen otorite": {"regex": r"self-signed|untrusted", "puan": 10},
        "SSLv2 destekleniyor": {"regex": r"SSLv2\s+enabled", "puan": 10},
        "SSLv3 destekleniyor": {"regex": r"SSLv3\s+enabled", "puan": 10},
        "TLS 1.0 destekleniyor": {"regex": r"TLSv1\s+enabled", "puan": 5},
        "TLS 1.1 destekleniyor": {"regex": r"TLSv1\.1\s+enabled", "puan": 5},
        "Sertifika 20 gunden az": {"regex": r"expires.*in less than 20 days", "puan": 5},
        "398 gunden uzun sertifika": {"regex": r"certificate validity:\s*(\d+)\s*days","puan": 5},
        "SHA-1/MD5 kullaniliyor": {"regex": r"sha1|md5", "puan": 10},
        "RSA anahtari kisa": {"regex": r"2048 bits|1024 bits", "puan": 5},
    }

    # Ek kontrol: sertifika 398 gunden uzun mu?
    expiration_kontrol = {
        "regex": r"certificate validity:\s*(\d+)\s*days",
        "puan": 5
    }

    if not os.path.exists(dosya):
        yorumlar.append("❌ sslyze_sonuc.txt dosyasi bulunamadi.")
        return "\n".join(yorumlar)

    with open(dosya, "r", encoding="utf-8") as f:
        veri = f.read().lower()

    for ad, kontrol in kriterler.items():
        if re.search(kontrol["regex"], veri):
            yorumlar.append(f"❌ {ad} tespit edildi. Ceza: -{kontrol['puan']} puan")
            puan -= kontrol["puan"]
        else:
            yorumlar.append(f"✅ {ad} tespit edilmedi.")

    # Sertifika validity süresi kontrolü (398 gün)
    m = re.search(expiration_kontrol["regex"], veri)
    if m:
        gun = int(m.group(1))
        if gun > 398:
            puan -= expiration_kontrol["puan"]
            yorumlar.append(f"❌ Sertifika {gun} gun gecerli (398 gunden uzun). Ceza: -{expiration_kontrol['puan']} puan")
        else:
            yorumlar.append(f"✅ Sertifika {gun} gun gecerli (398 gunden kisa).")
    else:
        yorumlar.append("❌ Sertifika gecerlilik suresi tespit edilemedi.")

    puan = max(puan, 0)
    yorumlar.append(f"SSL/TLS Guvenlik Puani: {puan} / 100")

    return "\n".join(yorumlar)


@mcp.tool()
def hesapla_nmap() -> str:
    """
    nmap_sonuc.txt dosyasini okuyarak servis taramasi ve zafiyetlere dayali puan hesaplar.
    ✅ / ❌ seklinde yorumlar dondurur.
    """
    dosya = "output/nmap_sonuc.txt"
    puan = 100
    yorumlar = ["--- Servis ve Zafiyet Taramasi (Nmap) ---"]
    ceza = 0

    tehlikeli_servisler = {
        "ftp": 10,
        "telnet": 20,
        "smtp": 10,
        "rdp": 15,
        "vnc": 15,
        "mysql": 10,
        "ms-sql": 10,
        "nfs": 10
    }

    zafiyet_regexleri = {
        "Heartbleed": r"ssl-heartbleed:.*VULNERABLE",
        "POODLE": r"ssl-poodle:.*VULNERABLE",
        "FREAK": r"freak:.*VULNERABLE",
        "Logjam": r"logjam:.*VULNERABLE",
        "Apache versiyon": r"apache.*(\d+\.\d+\.\d+)"
    }

    if not os.path.exists(dosya):
        yorumlar.append("❌ nmap_sonuc.txt dosyasi bulunamadi.")
        return "\n".join(yorumlar)

    with open(dosya, "r", encoding="utf-8") as file:
        satirlar = file.readlines()

    open_port_sayisi = 0
    icerik = "".join(satirlar).lower()

    # Port ve servis analizi
    for satir in satirlar:
        if "/tcp" in satir and "open" in satir:
            open_port_sayisi += 1
            for servis in tehlikeli_servisler:
                if servis in satir.lower():
                    yorumlar.append(f"❌ Tehlikeli servis acik: {servis.upper()} (ceza: -{tehlikeli_servisler[servis]})")
                    ceza += tehlikeli_servisler[servis]

    # Fazla port acikligi kontrolu
    ekstra_cekirdek = max(0, (open_port_sayisi - 3) * 2)
    if ekstra_cekirdek > 0:
        yorumlar.append(f"❌ 3'ten fazla port acik. Ekstra ceza: -{ekstra_cekirdek}")
        ceza += ekstra_cekirdek
    else:
        yorumlar.append("✅ Kritik port sayisi 3 veya daha az.")

    # Zafiyet taramalari
    for isim, regex in zafiyet_regexleri.items():
        if re.search(regex, icerik):
            yorumlar.append(f"❌ {isim} acigi tespit edildi.")
            ceza += 5
        else:
            yorumlar.append(f"✅ {isim} acigi tespit edilmedi.")

    puan -= ceza
    puan = max(puan, 0)
    yorumlar.append(f"Nmap Puani: {puan} / 100")

    return "\n".join(yorumlar)


@mcp.tool()
def hesapla_nikto() -> str:
    """
    nikto_sonuc.txt dosyasini okuyarak sadece Nikto'ya ozel zafiyetlere dayali puan hesaplar.
    PUT, yedek dosya, dizin listeleme, robots.txt, CORS wildcard gibi bulgulara odaklanir.
    """
    dosya = "output/nikto_sonuc.txt"
    puan = 100
    yorumlar = ["--- Web Sunucu Analizi (Nikto) ---"]

    if not os.path.exists(dosya):
        yorumlar.append("❌ nikto_sonuc.txt dosyasi bulunamadi.")
        return "\n".join(yorumlar)

    with open(dosya, "r", encoding="utf-8") as f:
        icerik = f.read().lower()

    # --- PUT metodu kontrolu ---
    if "allow: put" in icerik or "put is allowed" in icerik:
        yorumlar.append("❌ PUT metodu acik. Dosya yukleme yapilabilir.")
        puan -= 10
    else:
        yorumlar.append("✅ PUT metodu kapali.")

    # --- Yedek / hassas dosya kontrolu ---
    if re.search(r"\.(sql|zip|pem|cer|war|tar|gz|bak)", icerik):
        yorumlar.append("❌ Acikta hassas dosyalar bulundu (sql, zip vb).")
        puan -= 10
    else:
        yorumlar.append("✅ Hassas dosyalar tespit edilmedi.")

    # --- Dizin listeleme kontrolu ---
    if "index of" in icerik:
        yorumlar.append("❌ Dizin listelemesi acik (Index of).")
        puan -= 5
    else:
        yorumlar.append("✅ Dizin listelemesi yapilamiyor.")

    # --- robots.txt kontrolu ---
    if "robots.txt" in icerik and "200 ok" in icerik:
        yorumlar.append("❌ robots.txt mevcut, icinde gizli dizinler olabilir.")
        puan -= 5
    else:
        yorumlar.append("✅ robots.txt dosyasi bulunamadi.")

    # --- CORS wildcard kontrolu ---
    if "access-control-allow-origin: *" in icerik:
        yorumlar.append("❌ CORS wildcard tespit edildi. Tum alanlar izinli.")
        puan -= 5
    else:
        yorumlar.append("✅ CORS kisitlamasi yapilmis.")

    puan = max(puan, 0)
    yorumlar.append(f"Nikto Puani: {puan} / 100")

    return "\n".join(yorumlar)


@mcp.tool()
def hesapla_zap() -> str:
    """
    ZAP cikti dosyasini okuyarak sadece belirli basliklar uzerinden
    puan hesaplar ve aciklamali ✅ / ❌ satirlar olusturur.
    """
    dosya = "output/zap_report.txt"
    puan = 100
    yorumlar = ["--- ZAP Web Guvenlik Basliklari Analizi ---"]

    if not os.path.exists(dosya):
        yorumlar.append("❌ zap_report.txt dosyasi bulunamadi.")
        return "\n".join(yorumlar)

    try:
        with open(dosya, "r", encoding="utf-8") as f:
            icerik = f.read().lower()

        # Aranacak riskli ifadeler ve aciklamalar
        kontroller = [
            ("server information header exposed", -5, "Server header ifsasi ❌ Sunucu surum bilgisi ifsa edilmis."),
            ("x-frame-options is not deny or sameorigin", -5, "X-Frame-Options eksik ❌ Clickjacking riski."),
            ("csp is not implemented", -5, "CSP eksik ❌ Content Security Policy tanimli degil."),
            ("httponly cookies not used", -5, "HttpOnly eksik ❌ Client-side cookie erisimi mumkun."),
            ("x-content-type-options is not nosniff", -5, "X-Content-Type-Options eksik ❌ MIME sniffing acigi olabilir."),
            ("unmaintained page detected", -5, "Bakimsiz sayfa ❌ Saldiri yuzeyini artirir."),
            ("secure cookies used", 3, "Secure cookie ✅ Guvenli cookie kullaniliyor."),
            ("x-powered-by header not exposed", 2, "X-Powered-By gizlenmis ✅ Sunucu bilgisi gizli."),
            ("referrer policy is not unsafe-url", 2, "Referrer Policy ✅ Guvenli sekilde ayarlanmis."),
            ("asp.net version header not exposing specific version", 2, "ASP.NET versiyonu gizlenmis ✅ Surum bilgisi paylasilmiyor."),
            ("asp.net version header not exposed", 2, "ASP.NET header gizli ✅ Tamamen gizlenmis.")
        ]

        for ifade, ceza, yorum in kontroller:
            if ifade in icerik:
                yorumlar.append(yorum)
                puan += ceza
            else:
                # Eksik guvenlik onlemi varsa belirt
                if ceza > 0:
                    yorumlar.append(f"❌ {yorum.replace('❌', '').strip()}")
                else:
                    yorumlar.append(f"✅ {yorum.replace('✅', '').strip()}")

        puan = max(min(puan, 100), 0)
        yorumlar.append(f"ZAP Puani: {puan} / 100")

    except Exception as e:
        yorumlar.append(f"❌ Hata: {str(e)}")
        puan = 0

    return "\n".join(yorumlar)


@mcp.tool()
def genel_puanlama_ve_rapor(url: str) -> str:
    """
    Tüm hesapla_* fonksiyonlarını sırayla çalıştırır, puanları toplar ve sonucu string olarak döndürür.
    """
    toplam = 0
    max_puan = 0
    rapor_satirlari = []

    # Kullanmak istediğimiz analiz fonksiyonları
    fonksiyonlar = [
        hesapla_abuseipdb,
        hesapla_email,
        hesapla_sslyze,
        hesapla_dns,
        hesapla_nmap,
        hesapla_nikto,
        hesapla_zap,
    ]

    for hesapla in fonksiyonlar:
        try:
            sonuc = hesapla()
            # Sonuçtan puanı çıkar
            puan_match = re.search(r"Puani:\s*(\d+)\s*/\s*100", sonuc)
            if puan_match:
                puan = int(puan_match.group(1))
            toplam += puan
            max_puan += 100
            rapor_satirlari.append(sonuc)
        except Exception as e:
            rapor_satirlari.append(f"❌ {hesapla.__name__} çalıştırırken hata: {e}")

    genel_puan = round((toplam / max_puan) * 100) if max_puan > 0 else 0

    rapor_metni = f"Hedef: {url}\nToplam Güvenlik Puanı: {genel_puan} / 100\n\n" + "\n\n".join(rapor_satirlari)

    os.makedirs("output", exist_ok=True)
    with open("output/rapor.txt", "w", encoding="utf-8") as f:
        f.write(rapor_metni)

    return rapor_metni 