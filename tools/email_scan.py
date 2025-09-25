from mcp_instance import mcp
import dns.resolver
import os
from urllib.parse import urlparse

def parse_domain(target):
    parsed = urlparse(target)
    domain = parsed.hostname if parsed.hostname else parsed.path
    if domain.count('.') > 2:
        domain = '.'.join(domain.split('.')[-2:])
    return domain

@mcp.tool()
def email_scan(target_url: str) -> str:
    """
    Verilen hedef için email güvenlik (DMARC, SPF) kontrollerini yapar, sonucu string olarak döndürür.
    """
    domain = parse_domain(target_url)
    results = []

    # DMARC kontrolü
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        try:
            dmarc_record = ''.join(s.decode() for s in dmarc_answers[0].strings)
        except AttributeError:
            dmarc_record = ''.join(dmarc_answers[0].strings)

        results.append("Email\tDMARC policy exists\t✅\tDMARC politikası tanımlı.")
        if "p=none" in dmarc_record:
            results.append("Email\tDMARC policy is p=none\t❌\tDMARC politikası `p=none`; koruma sağlamaz.")
        else:
            results.append("Email\tDMARC policy is strict\t✅\tDMARC politikası koruma sağlar.")
    except Exception:
        results.append("Email\tDMARC policy exists\t❌\tDMARC kaydı bulunamadı.")

    # SPF kontrolü
    try:
        spf_record = None
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            try:
                txt = ''.join(s.decode() for s in r.strings)
            except AttributeError:
                txt = ''.join(r.strings)

            if txt.startswith("v=spf1"):
                spf_record = txt
                break

        if spf_record:
            results.append("Email\tSPF enabled\t✅\tSPF etkin.")
            if "+all" in spf_record:
                results.append("Email\tStrict SPF filtering - not using +all\t❌\tSPF kaydında +all kullanılmış (gevşek).")
            else:
                results.append("Email\tStrict SPF filtering - not using +all\t✅\tSPF yalnızca izinli alanlara izin verecek şekilde yapılandırılmış.")
            if "ptr" in spf_record:
                results.append("Email\tSPF ptr mechanism not used\t❌\tPTR mekanizması kullanılmış.")
            else:
                results.append("Email\tSPF ptr mechanism not used\t✅\tPTR mekanizması kullanılmamış.")
            if spf_record.count(" ") > 1 and spf_record.startswith("v=spf1"):
                results.append("Email\tSPF syntax correct\t✅\tSPF söz dizimi doğru.")
            else:
                results.append("Email\tSPF syntax correct\t❌\tSPF söz dizimi hatalı olabilir.")
        else:
            results.append("Email\tSPF enabled\t❌\tSPF kaydı bulunamadı.")
    except Exception:
        results.append("Email\tSPF enabled\t❌\tSPF sorgusu sırasında hata oluştu.")

    # Sonucu dosyaya kaydet
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "email_sonuc.txt")
    
    final_result = "\n".join(results)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(final_result)

    return final_result 