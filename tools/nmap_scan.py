from mcp_instance import mcp
import subprocess
import os
import re
from urllib.parse import urlparse

@mcp.tool()
def nmap_scan(target_url: str) -> str:
    """
    Hedef URL/IP üzerinde Nmap taraması yapar ve sonucu string olarak döndürür.
    """
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname if parsed.hostname else target_url

        # Proje root dizinini belirle
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(project_root, "output")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "nmap_sonuc.txt")

        # Proje içindeki nmap'i kullan
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