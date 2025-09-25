#!/usr/bin/env python3
"""
Araçları test etmek için script
"""

import os
import sys
import traceback

print("1. Python yolu ve çalışma dizini:")
print(f"Python: {sys.executable}")
print(f"Çalışma dizini: {os.getcwd()}")

print("\n2. Modülleri import etmeye çalışıyorum...")
try:
    from mcp_instance import mcp
    print("✅ mcp_instance import edildi")
except Exception as e:
    print(f"❌ mcp_instance import hatası: {e}")
    traceback.print_exc()

try:
    import main
    print("✅ main modülü import edildi")
except Exception as e:
    print(f"❌ main modülü import hatası: {e}")
    traceback.print_exc()

print("\n3. MCP araçlarını kontrol ediyorum...")
try:
    if hasattr(mcp, 'tools'):
        print(f"MCP araçları: {mcp.tools}")
    else:
        print("❌ mcp.tools bulunamadı")
except Exception as e:
    print(f"❌ MCP araçları kontrolünde hata: {e}")

print("\n4. Araçları test ediyorum...")
try:
    # tum_araclari_calistir fonksiyonuna erişim denemesi
    if hasattr(main, 'tum_araclari_calistir'):
        print("✅ main.tum_araclari_calistir fonksiyonu bulundu")
        try:
            print("Test çalıştırılıyor...")
            # Burada çalıştırmıyoruz sadece erişimi test ediyoruz
        except Exception as e:
            print(f"❌ Çalıştırma hatası: {e}")
    else:
        print("❌ main.tum_araclari_calistir fonksiyonu bulunamadı")
        
    # Diğer araçları kontrol et
    from tools.nikto_scan import nikto_scan
    print("✅ nikto_scan fonksiyonu bulundu")
    from tools.nmap_scan import nmap_scan
    print("✅ nmap_scan fonksiyonu bulundu")
    
except Exception as e:
    print(f"❌ Fonksiyon testi hatası: {e}")
    traceback.print_exc()

print("\n5. MCP sunucu araçları test ediliyor...")
try:
    # mcp_server dosyasındaki araçları test et
    from importlib import import_module
    try:
        mcp_server = import_module('mcp_server')
        print("✅ mcp_server modülü import edildi")
        
        if hasattr(mcp_server, 'tum_araclari_calistir_internal'):
            print("✅ mcp_server.tum_araclari_calistir_internal fonksiyonu bulundu")
        else:
            print("❌ mcp_server.tum_araclari_calistir_internal fonksiyonu bulunamadı")
            
        if hasattr(mcp_server, 'server'):
            print("✅ mcp_server.server nesnesi bulundu")
            print(f"Server araçları: {getattr(mcp_server.server, 'tools', 'Araç bilgisine erişilemiyor')}")
        else:
            print("❌ mcp_server.server nesnesi bulunamadı")
    
    except Exception as e:
        print(f"❌ mcp_server import hatası: {e}")
        traceback.print_exc()
        
except Exception as e:
    print(f"❌ MCP sunucu testi hatası: {e}")
    traceback.print_exc()

print("\nTest tamamlandı!") 