#!/usr/bin/env python3
"""
MCP Server başlatma dosyası
"""

import asyncio
import sys
import os

# Çalışma dizinini ayarla
os.chdir(os.path.dirname(os.path.abspath(__file__)))

def main():
    """MCP server'ı başlat"""
    try:
        # Import'ları burada yap
        from mcp_instance import mcp
        import main  # noqa: F401
        
        print("MCP Server başlatılıyor...", file=sys.stderr)
        
        # Yeni event loop oluştur
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Server'ı çalıştır
        loop.run_until_complete(mcp.run())
        
    except Exception as e:
        print(f"MCP Server hatası: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("MCP Server durduruldu.", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Başlatma hatası: {e}", file=sys.stderr)
        sys.exit(1) 