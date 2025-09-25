from mcp_instance import mcp
import os
import sys
import traceback
import time
import datetime
from tools.nikto_scan import nikto_scan
from tools.nmap_scan import nmap_scan
from tools.abuseipdb_check import abuseipdb_scan
from tools.zap_scan import zap_scan
from tools.sslyze_scan import sslyze_scan
from tools.dns_scan import dns_scan
from tools.email_scan import email_scan
from dotenv import load_dotenv
from tools.skor_hesaplayici import genel_puanlama_ve_rapor

load_dotenv()

@mcp.tool()
def tum_araclari_calistir(hedef: str) -> str:
    """
    Verilen hedef icin tum guvenlik araclarini calistirir ve genel raporu dondurur.
    """
    start_time = time.time()
    sonuc_metni = []
    
    def log_adim(mesaj):
        """Hem listeye ekle hem de ekrana yazdir"""
        sonuc_metni.append(mesaj)
        print(mesaj)
    
    log_adim("\n======================================================================")
    log_adim(f"[TARAMA] {hedef} icin guvenlik taramasi baslatiliyor...")
    log_adim(f"[ZAMAN] Baslangic zamani: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_adim("======================================================================\n")
    
    # Output dizinini kontrol et
    project_root = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(project_root, "output")
    os.makedirs(output_dir, exist_ok=True)
    
    raporlar = []
    completed_scans = 0
    total_scans = 8  # Toplam tarama sayisi
    
    def update_progress():
        nonlocal completed_scans
        completed_scans += 1
        percent = (completed_scans / total_scans) * 100
        elapsed = time.time() - start_time
        
        log_adim(f"\n[ILERLEME] {completed_scans}/{total_scans} tarama tamamlandi ({percent:.1f}%)")
        log_adim(f"[SURE] Gecen sure: {elapsed:.1f} saniye")
        log_adim("==================================================\n")
    
    def run_tool(tool_func, *args, name="Bilinmeyen Arac"):
        """Bir araci guvenli bir sekilde calistir"""
        try:
            result = tool_func(*args)
            log_adim(f"  +-- [TAMAM] {name} taramasi tamamlandi")
            update_progress()
            return result
        except Exception as e:
            error_msg = f"  +-- [HATA] {name} calistirilirken hata olustu: {e}\n{traceback.format_exc()}"
            log_adim(error_msg)
            
            # Hata durumunda output dosyasini olustur
            output_path = os.path.join(output_dir, f"{name.lower().replace(' ', '_')}_sonuc.txt")
            
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"{name} Tarama Hatasi: {e}\n\n{error_msg}")
            
            update_progress()
            return f"[-] {name} calistirilirken hata olustu: {e}"

    # AbuseIPDB taramasi
    log_adim(f"\n[TARAMA] [1/{total_scans}] AbuseIPDB IP guvenlik taramasi baslatiliyor...")
    log_adim("  +-- IP adresi cozumluyor...")
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    abuseipdb_sonuc = run_tool(abuseipdb_scan, hedef, api_key, name="AbuseIPDB")
    raporlar.append(f"AbuseIPDB Sonucu:\n{abuseipdb_sonuc}")

    # Email taramasi
    log_adim(f"\n[TARAMA] [2/{total_scans}] Email guvenligi taramasi baslatiliyor...")
    log_adim("  +-- SPF kayitlari kontrol ediliyor...")
    log_adim("  +-- DMARC kayitlari kontrol ediliyor...")
    email_sonuc = run_tool(email_scan, hedef, name="Email Guvenligi")
    raporlar.append(f"Email Sonucu:\n{email_sonuc}")

    # DNS taramasi
    log_adim(f"\n[TARAMA] [3/{total_scans}] DNS & WHOIS taramasi baslatiliyor...")
    log_adim("  +-- DNS kayitlari sorgulaniyor...")
    log_adim("  +-- WHOIS bilgileri aliniyor...")
    dns_sonuc = run_tool(dns_scan, hedef, name="DNS Kontrolu")
    raporlar.append(f"DNS Sonucu:\n{dns_sonuc}")

    # SSLyze taramasi
    log_adim(f"\n[TARAMA] [4/{total_scans}] SSL/TLS detayli guvenlik taramasi baslatiliyor...")
    log_adim("  +-- SSL sertifikasi kontrol ediliyor...")
    log_adim("  +-- Sifreleme protokolleri ve algoritmalar analiz ediliyor...")
    log_adim("  +-- SSL/TLS yapilandirmasi test ediliyor...")
    sslyze_sonuc = run_tool(sslyze_scan, hedef, name="SSLyze")
    raporlar.append(f"SSLyze Sonucu:\n{sslyze_sonuc}")

    # Nmap taramasi
    log_adim(f"\n[TARAMA] [5/{total_scans}] Nmap port ve servis taramasi baslatiliyor...")
    log_adim("  +-- Hedef portlar ve servisler taraniyor...")
    log_adim("  +-- SSL/TLS guvenlik kontrolleri yapiliyor...")
    log_adim("  +-- Guvenlik aciklari kontrol ediliyor...")
    nmap_sonuc = run_tool(nmap_scan, hedef, name="Nmap")
    raporlar.append(f"Nmap Sonucu:\n{nmap_sonuc}")

    # Nikto taramasi
    log_adim(f"\n[TARAMA] [6/{total_scans}] Nikto web zafiyet taramasi baslatiliyor...")
    log_adim("  +-- Web sunucu zafiyetleri taraniyor (bu islem biraz zaman alabilir)...")
    log_adim("  +-- Bilinen guvenlik aciklari kontrol ediliyor...")
    nikto_sonuc = run_tool(nikto_scan, hedef, name="Nikto")
    raporlar.append(f"Nikto Sonucu:\n{nikto_sonuc}")

    # ZAP taramasi
    log_adim(f"\n[TARAMA] [7/{total_scans}] ZAP web guvenlik basliklari taramasi baslatiliyor...")
    log_adim("  +-- HTTP guvenlik basliklari kontrol ediliyor...")
    log_adim("  +-- Web uygulama guvenligi analiz ediliyor...")
    zap_sonuc = run_tool(zap_scan, hedef, name="ZAP")
    raporlar.append(f"ZAP Sonucu:\n{zap_sonuc}")

    # Genel puanlama ve rapor
    log_adim(f"\n[TARAMA] [8/{total_scans}] Genel guvenlik puani ve rapor hazirlaniyor...")
    log_adim("  +-- Tum tarama sonuclari degerlendiriliyor...")
    log_adim("  +-- Guvenlik puani hesaplaniyor...")
    try:
        genel_rapor = genel_puanlama_ve_rapor(hedef)
        raporlar.append(f"Genel Puanlama ve Rapor:\n{genel_rapor}")
        log_adim("  +-- [TAMAM] Genel rapor hazirlandi")
        update_progress()
    except Exception as e:
        error_msg = f"  +-- [HATA] Genel puanlama ve rapor olusturulurken hata olustu: {e}"
        log_adim(error_msg)
        raporlar.append(error_msg)
        update_progress()

    # Sonuc raporunu dosyaya yaz
    try:
        rapor_dosyasi = os.path.join(output_dir, "tam_rapor.txt")
        with open(rapor_dosyasi, "w", encoding="utf-8") as f:
            f.write("\n\n" + "="*50 + "\n\n".join(raporlar))
        log_adim(f"\n[RAPOR] Tam rapor kaydedildi: {rapor_dosyasi}")
    except Exception as e:
        log_adim(f"\n[HATA] Rapor dosyaya yazilamadi: {e}")
    
    # Ozet
    total_time = time.time() - start_time
    log_adim("\n======================================================================")
    log_adim("[TAMAM] Tum taramalar tamamlandi!")
    log_adim(f"[ZAMAN] Toplam sure: {total_time:.1f} saniye ({total_time/60:.1f} dakika)")
    log_adim(f"[OZET] Tamamlanan tarama sayisi: {completed_scans}/{total_scans}")
    log_adim(f"[DOSYA] Rapor dosyasi: {rapor_dosyasi}")
    log_adim("======================================================================\n")
    
    # Genel puanlama sonucunu da ekle
    try:
        log_adim("\n" + genel_rapor)
    except Exception:
        log_adim("\n[HATA] Genel puan hesaplanamadi")

    # Tum sonuclari dondur
    return "\n".join(sonuc_metni)