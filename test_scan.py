#!/usr/bin/env python3
"""
Güvenlik tarama araçlarını direkt çağıran test script'i
"""

import os
import sys
import traceback
from urllib.parse import urlparse
import time
import datetime

def test_scan(target_url):
    """Tüm araçları test amaçlı çalıştıran fonksiyon"""
    start_time = time.time()
    print(f"\n{'='*70}")
    print(f"🔍 {target_url} için güvenlik taraması başlatılıyor...")
    print(f"🕙 Başlangıç zamanı: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")
    
    # Output dizinini kontrol et
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(output_dir, exist_ok=True)
    
    raporlar = []
    completed_scans = 0
    total_scans = 8  # Toplam tarama sayısı
    
    def update_progress():
        nonlocal completed_scans
        completed_scans += 1
        percent = (completed_scans / total_scans) * 100
        elapsed = time.time() - start_time
        
        print(f"\n📊 İlerleme: {completed_scans}/{total_scans} tarama tamamlandı ({percent:.1f}%)")
        print(f"⏱️ Geçen süre: {elapsed:.1f} saniye")
        print(f"{'='*50}\n")
    
    # AbuseIPDB taraması
    try:
        print(f"\n🔍 [1/{total_scans}] AbuseIPDB IP güvenlik taraması başlatılıyor...")
        from tools.abuseipdb_check import abuseipdb_scan
        api_key = os.getenv("ABUSEIPDB_API_KEY", "eda7426bb70f158e7e726e839b36b07b42a6d4fb95ba1fae25d2190701e895c4393a42f0bd170c5c")
        print("  ├─ IP adresi çözümleniyor...")
        abuseipdb_sonuc = abuseipdb_scan(target_url, api_key)
        raporlar.append(f"AbuseIPDB Sonucu:\n{abuseipdb_sonuc}")
        print("  └─ ✅ AbuseIPDB taraması tamamlandı")
        update_progress()
    except Exception as e:
        error_msg = f"  └─ ❌ AbuseIPDB taraması başarısız: {e}"
        print(error_msg)
        print(traceback.format_exc())
        raporlar.append(error_msg)
        update_progress()
    
    # Email taraması
    try:
        print(f"\n🔍 [2/{total_scans}] Email güvenliği taraması başlatılıyor...")
        from tools.email_scan import email_scan
        print("  ├─ SPF kayıtları kontrol ediliyor...")
        print("  ├─ DMARC kayıtları kontrol ediliyor...")
        email_sonuc = email_scan(target_url)
        raporlar.append(f"Email Sonucu:\n{email_sonuc}")
        print("  └─ ✅ Email taraması tamamlandı")
        update_progress()
    except Exception as e:
        error_msg = f"  └─ ❌ Email taraması başarısız: {e}"
        print(error_msg)
        print(traceback.format_exc())
        raporlar.append(error_msg)
        update_progress()
    
    # DNS taraması
    try:
        print(f"\n🔍 [3/{total_scans}] DNS & WHOIS taraması başlatılıyor...")
        from tools.dns_scan import dns_scan
        print("  ├─ DNS kayıtları sorgulanıyor...")
        print("  ├─ WHOIS bilgileri alınıyor...")
        dns_sonuc = dns_scan(target_url)
        raporlar.append(f"DNS Sonucu:\n{dns_sonuc}")
        print("  └─ ✅ DNS taraması tamamlandı")
        update_progress()
    except Exception as e:
        error_msg = f"  └─ ❌ DNS taraması başarısız: {e}"
        print(error_msg)
        print(traceback.format_exc())
        raporlar.append(error_msg)
        update_progress()
    
    # Nmap taraması
    try:
        print(f"\n🔍 [4/{total_scans}] Nmap port ve servis taraması başlatılıyor...")
        from tools.nmap_scan import nmap_scan
        print("  ├─ Hedef portlar ve servisler taranıyor...")
        print("  ├─ SSL/TLS güvenlik kontrolleri yapılıyor...")
        print("  ├─ Güvenlik açıkları kontrol ediliyor...")
        nmap_sonuc = nmap_scan(target_url)
        raporlar.append(f"Nmap Sonucu:\n{nmap_sonuc}")
        print("  └─ ✅ Nmap taraması tamamlandı")
        update_progress()
    except Exception as e:
        error_msg = f"  └─ ❌ Nmap taraması başarısız: {e}"
        print(error_msg)
        print(traceback.format_exc())
        raporlar.append(error_msg)
        update_progress()
    
    # ZAP taraması
    try:
        print(f"\n🔍 [5/{total_scans}] ZAP web güvenlik başlıkları taraması başlatılıyor...")
        from tools.zap_scan import zap_scan
        print("  ├─ HTTP güvenlik başlıkları kontrol ediliyor...")
        print("  ├─ Web uygulama güvenliği analiz ediliyor...")
        zap_sonuc = zap_scan(target_url)
        raporlar.append(f"ZAP Sonucu:\n{zap_sonuc}")
        print("  └─ ✅ ZAP taraması tamamlandı")
        update_progress()
    except Exception as e:
        error_msg = f"  └─ ❌ ZAP taraması başarısız: {e}"
        print(error_msg)
        print(traceback.format_exc())
        raporlar.append(error_msg)
        update_progress()
    
    # SSLyze taraması
    try:
        print(f"\n🔍 [6/{total_scans}] SSL/TLS detaylı güvenlik taraması başlatılıyor...")
        from tools.sslyze_scan import sslyze_scan
        print("  ├─ SSL sertifikası kontrol ediliyor...")
        print("  ├─ Şifreleme protokolleri ve algoritmalar analiz ediliyor...")
        print("  ├─ SSL/TLS yapılandırması test ediliyor...")
        sslyze_sonuc = sslyze_scan(target_url)
        raporlar.append(f"SSLyze Sonucu:\n{sslyze_sonuc}")
        print("  └─ ✅ SSLyze taraması tamamlandı")
        update_progress()
    except Exception as e:
        error_msg = f"  └─ ❌ SSLyze taraması başarısız: {e}"
        print(error_msg)
        print(traceback.format_exc())
        raporlar.append(error_msg)
        update_progress()
    
    # Nikto taraması - en sona
    try:
        print(f"\n🔍 [7/{total_scans}] Nikto web zafiyet taraması başlatılıyor...")
        from tools.nikto_scan import nikto_scan
        print("  ├─ Web sunucu zafiyetleri taranıyor (bu işlem biraz zaman alabilir)...")
        print("  ├─ Bilinen güvenlik açıkları kontrol ediliyor...")
        nikto_sonuc = nikto_scan(target_url)
        raporlar.append(f"Nikto Sonucu:\n{nikto_sonuc}")
        print("  └─ ✅ Nikto taraması tamamlandı")
        update_progress()
    except Exception as e:
        error_msg = f"  └─ ❌ Nikto taraması başarısız: {e}"
        print(error_msg)
        print(traceback.format_exc())
        raporlar.append(error_msg)
        update_progress()
    
    # Genel rapor
    try:
        print(f"\n🔍 [8/{total_scans}] Genel güvenlik puanı ve rapor hazırlanıyor...")
        from tools.skor_hesaplayici import genel_puanlama_ve_rapor
        print("  ├─ Tüm tarama sonuçları değerlendiriliyor...")
        print("  ├─ Güvenlik puanı hesaplanıyor...")
        genel_rapor = genel_puanlama_ve_rapor(target_url)
        raporlar.append(f"Genel Rapor:\n{genel_rapor}")
        print("  └─ ✅ Genel rapor hazırlandı")
        update_progress()
    except Exception as e:
        error_msg = f"  └─ ❌ Genel rapor hazırlanamadı: {e}"
        print(error_msg)
        print(traceback.format_exc())
        raporlar.append(error_msg)
        update_progress()
    
    # Sonuç raporunu dosyaya yaz
    try:
        rapor_dosyasi = os.path.join(output_dir, "tam_rapor.txt")
        with open(rapor_dosyasi, "w", encoding="utf-8") as f:
            f.write("\n\n" + "="*50 + "\n\n".join(raporlar))
        print(f"\n📄 Tam rapor kaydedildi: {rapor_dosyasi}")
    except Exception as e:
        print(f"\n❌ Rapor dosyaya yazılamadı: {e}")
    
    # Özet
    total_time = time.time() - start_time
    print(f"\n{'='*70}")
    print(f"✅ Tüm taramalar tamamlandı!")
    print(f"🕙 Toplam süre: {total_time:.1f} saniye ({total_time/60:.1f} dakika)")
    print(f"📊 Tamamlanan tarama sayısı: {completed_scans}/{total_scans}")
    print(f"📁 Rapor dosyası: {rapor_dosyasi}")
    print(f"{'='*70}\n")
    
    # Sadece genel puanlamayı göster
    try:
        from tools.skor_hesaplayici import genel_puanlama_ve_rapor
        return genel_puanlama_ve_rapor(target_url)
    except Exception as e:
        return "❌ Genel puan hesaplanamadı: " + str(e)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python test_scan.py <hedef_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    sonuc = test_scan(target_url)
    print("\n" + "="*60)
    print(sonuc) 