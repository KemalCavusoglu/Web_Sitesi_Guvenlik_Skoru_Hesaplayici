# Web Sitesi Güvenlik Skoru hesaplayıcı (MCP ile)

Web Sitesi Güvenlik Skoru hesaplayıcı, web sitelerinin güvenlik düzeyini analiz eden ve puanlayan kapsamlı bir güvenlik tarama aracıdır. Cursor MCP (Model Context Protocol) entegrasyonunu kullanarak, farklı güvenlik araçlarını tek bir çatı altında birleştirir.

## Özellikler

- **Çoklu Tarama Araçları**: Nmap, Nikto, SSLyze, AbuseIPDB ve daha fazlası
- **Entegre Puanlama**: Her bir araç ve genel güvenlik skoru hesaplama
- **Detaylı Rapor**: Kapsamlı güvenlik analizi ve zafiyet raporları
- **Cursor MCP Entegrasyonu**: Cursor IDE üzerinden doğrudan kullanım
- **Lokalizasyon**: Türkçe arayüz ve raporlar

## Kullanılan Araçlar

- **[AbuseIPDB](https://www.abuseipdb.com/)**: IP adresi güvenlik kontrolü
- **[Nmap](https://nmap.org/)**: Port taraması ve servis keşfi
- **[Nikto](https://cirt.net/Nikto2)**: Web sunucusu zafiyet taraması
- **[SSLyze](https://github.com/nabla-c0d3/sslyze)**: SSL/TLS yapılandırma analizi
- **[ZAP (Zed Attack Proxy)](https://www.zaproxy.org/)**: Web uygulama güvenlik taraması
- **DNS & WHOIS**: Alan adı bilgileri ve DNS yapılandırma kontrolü
- **Email Güvenlik Kontrolü**: SPF, DMARC kayıtları kontrolü

## Kurulum

### Gereksinimler

- Python 3.10 veya üzeri
- [Cursor IDE](https://cursor.sh/) (MCP entegrasyonu için)
- Perl (Nikto için)

### Bağımlılıkları Yükleme

```bash
pip install -r requirements.txt
```

veya [uv](https://github.com/astral-sh/uv) ile:

```bash
uv pip install -e .
```

### API Anahtarları

Bazı özellikler API anahtarları gerektirmektedir. Bunları `.env` dosyasında ayarlayabilirsiniz:

```
ABUSEIPDB_API_KEY=your_api_key_here
WHOIS_API_KEY=your_api_key_here
```

## Kullanım

### Doğrudan Çalıştırma

```bash
python test_scan.py example.com
```

### MCP Sunucusu Olarak Çalıştırma

```bash
python run_server.py
```

### Cursor IDE Entegrasyonu

Cursor IDE'de, MCP sunucusuna bağlanarak aşağıdaki komutu kullanabilirsiniz:

```
/tool tum_araclari_calistir hedef=example.com
```

## Proje Yapısı

```
.
├── main.py                  # Ana MCP tool tanımları
├── mcp_instance.py          # Web Sitesi Güvenlik Skoru MCP örneği
├── mcp_server.py            # MCP sunucu yapılandırması
├── run_server.py            # MCP sunucusunu başlatan script
├── tools/                   # Tarama araçları
│   ├── abuseipdb_check.py   # AbuseIPDB entegrasyonu
│   ├── dns_scan.py          # DNS tarama aracı
│   ├── email_scan.py        # Email güvenlik tarama aracı
│   ├── nikto_scan.py        # Nikto tarama entegrasyonu
│   ├── nmap_scan.py         # Nmap entegrasyonu
│   ├── skor_hesaplayici.py  # Güvenlik puanlama modülü
│   ├── sslyze_scan.py       # SSLyze entegrasyonu
│   └── zap_scan.py          # ZAP entegrasyonu
├── output/                  # Çıktı dosyaları
├── test_scan.py             # Test amaçlı tarama script'i
└── test_tools.py            # Araç testi
```

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

## Katkıda Bulunma

Katkıda bulunmak isterseniz lütfen bir Issue açın veya Pull Request gönderin.

## İletişim

[GitHub Issues](https://github.com/KemalCavusoglu/WebSitesiGuvenlikSkoru/issues) üzerinden sorularınızı iletebilirsiniz.

---

Not: Bu araç yalnızca eğitim amaçlıdır ve sadece kendi sahip olduğunuz veya izin aldığınız sistemlerde kullanılmalıdır.
