#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNSniper (dnsniper.py) - Professional DNS Enumeration & Exploitation Tool
Author: Sirius

Özellikleri ve Pentest Notları:
- **Zafiyet Tespiti (Zone Transfer - AXFR):** Yanlış yapılandırılmış DNS sunucularında
  tüm DNS kayıtlarının dışarı sızmasına yol açan Zone Transfer zafiyetini otomatik dener.
  Bir kurumun sahip olduğu tüm sub-domainleri tek seferde öğrenmek için en kritik keşif tekniğidir.
- **DMARC ve SPF Analizi:** TXT kayıtlarını filtreleyerek SPF ve DMARC konfigürasyon 
  hatalarını arar. Bu hatalar, kurum adına sahte e-posta gönderilebilmesine (Email Spoofing) yol açar.
- **Kapsamlı DNS Sorguları:** Standart kayıtların (A, AAAA, MX, NS, CNAME) yanı sıra
  yetki ve yönetim (SOA) kayıtlarını da denetler.
- **Custom Nameserver:** `--nameserver` parametresiyle WAF'a takılmadan veya iç ağda
  bulunan bir yerel DNS sunucusu üzerinde sorgulama yapılabilir.
- **OS Uyumluluğu:** Windows (`cls`) ve Linux/Mac (`clear`) sistemlerinde ekran temizleme sorunu giderildi.
"""

import argparse
import os
import sys
import dns.resolver
import dns.query
import dns.zone
from colorama import init, Fore, Style

try:
    from pyfiglet import Figlet
except ImportError:
    print("[-] pyfiglet kütüphanesi eksik. Lütfen yükleyin: pip install pyfiglet")
    sys.exit(1)

# Colorama Başlatma (Terminal renkleri için)
init(autoreset=True)

def clear_screen():
    # Windows platformunda 'clear' hatasını önlemek için 'nt' (Windows) tespiti
    os.system("cls" if os.name == "nt" else "clear")

def print_banner():
    f = Figlet(font='slant', width=100)
    print(Fore.MAGENTA + Style.BRIGHT + f.renderText('DNSniper'))
    str_info = "                      | - |  By : Sirius - Penetration Tester | - |         "
    print(Fore.RED + Style.BRIGHT + str_info + "\n" + Fore.RESET)

def perform_zone_transfer(domain, nameservers):
    """
    Sızma testlerinde (Pentest) en kritik DNS keşif adımıdır. 'AXFR' zafiyetini test eder.
    Tüm alan adlarının sızması, saldırgan için hazine niteliğindedir.
    """
    print(Fore.CYAN + Style.BRIGHT + f"\n[*] Zone Transfer (AXFR) Zafiyeti Test Ediliyor..." + Fore.RESET)
    vulnerable = False
    
    for ns in nameservers:
        # NS isimleri genelde 'ns1.example.com' şeklinde gelir, DNS sorgusu ile IP adresine çevrilmeli.
        try:
            ns_ips = [ip.to_text() for ip in dns.resolver.resolve(ns, 'A')]
        except Exception:
            # IP resolve edilemediyse atla
            continue
            
        for ns_ip in ns_ips:
            try:
                print(Fore.BLUE + f"  [~] {ns} ({ns_ip}) sunucusundan AXFR deneniyor...")
                # dns.query.xfr üzerinden Transfer işlemi
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                
                print(Fore.GREEN + Style.BRIGHT + f"  [+] KRİTİK ZAFİYET BULUNDU! Zone Transfer Başarılı: {ns} ({ns_ip})")
                vulnerable = True
                
                count = 0
                for name, node in zone.nodes.items():
                    print(Fore.RED + f"      -> {name}.{domain}")
                    count += 1
                    # Çok uzun bir liste olabileceğinden ekrana bir kısmını bastırıyoruz
                    # (Pentester sonradan aracı bir dosyaya yönlendirerek hepsini çekebilir)
                    if count >= 30:
                        print(Fore.GREEN + f"      ... ve daha fazlası. (Toplam {len(zone.nodes)} kayıt sızdırıldı)")
                        break
                        
            except Exception as e:
                print(Fore.YELLOW + f"  [-] Başarısız: Sunucu talebi reddetti veya yetki yok.")

    if not vulnerable:
        print(Fore.GREEN + "  [+] Hiçbir name server'da Zone Transfer zafiyeti tespit edilmedi." + Fore.RESET)
        
    return vulnerable

def check_email_spoofing(txt_records):
    """
    TXT kayıtlarında SPF (Sender Policy Framework) veya DMARC kayıtlarını analiz eder.
    Eğer zayıf bir kayıt varsa, saldırgan hedef domain'den geliyormuş gibi "phishing" gönderebilir.
    """
    spf_found = False
    dmarc_found = False
    
    for record in txt_records:
        record_lower = record.lower()
        if "v=spf1" in record_lower:
            spf_found = True
            if "~all" in record_lower:
                print(Fore.YELLOW + "      [!] SPF Kaydı SoftFail (~all) kullanıyor. Domain itibarı güçlü değilse email spoofing yapılabilir.")
            elif "-all" in record_lower:
                print(Fore.GREEN + "      [+] Güvenli: SPF Kaydı HardFail (-all) kullanıyor.")
            elif "+all" in record_lower or "?all" in record_lower:
                print(Fore.RED + Style.BRIGHT + "      [!] DİKKAT: SPF Kaydı çok zayıf (+all veya ?all). Email Spoofing saldırısına oldukça açık!")
                
        if "v=dmarc1" in record_lower:
             dmarc_found = True
             if "p=none" in record_lower:
                 print(Fore.YELLOW + "      [!] DMARC Politikası İzlemekte (p=none). SPF ihlallerinde engelleme yapmayacak.")
             else:
                 print(Fore.GREEN + "      [+] Güvenli: DMARC politikası (p=quarantine veya p=reject) tanımlı.")
                
    if not spf_found and txt_records and "Kayıt bulunamadı" not in txt_records[0]:
         print(Fore.RED + Style.BRIGHT + "      [!] DİKKAT: Herhangi bir SPF kaydı bulunamadı! Domain adınıza sahte (spoof) e-posta gönderilebilir.")

def resolve_dns_records(domain, custom_ns=None):
    """
    Hedef domain için temel ve kritik DNS kayıtlarını süpürür.
    """
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results = {}
    
    resolver = dns.resolver.Resolver()
    if custom_ns:
         resolver.nameservers = [custom_ns]

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            results[record_type] = [answer.to_text() for answer in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = ["Kayıt bulunamadı"]
        except dns.resolver.NXDOMAIN:
            results[record_type] = ["Domain mevcut değil (NXDOMAIN)"]
        except Exception as e:
            results[record_type] = [f"Hata: {str(e)}"]

    return results

def save_results(domain, results, output_file):
    """Sonuçları terminal kirliliği olmadan dosyaya detaylı aktarır."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"DNSniper Sonuçları - {domain}\n")
            f.write("="*40 + "\n\n")
            for record_type, records in results.items():
                f.write(f"[{record_type} Kayıtları]\n")
                for record in records:
                    f.write(f"  {record}\n")
                f.write("\n")
    except Exception as e:
        print(Fore.RED + f"\n[!] Dosya kaydedilemedi: {e}")

def print_results(domain, results):
    print(Fore.CYAN + Style.BRIGHT + f"\n[*] Hedef: {domain} için DNS Kayıt Analizi" + Fore.RESET)
    
    for record_type, records in results.items():
        print(Fore.BLUE + Style.BRIGHT + f"\n[{record_type} Kayıtları]:" + Fore.RESET)
        for record in records:
            if "Kayıt bulunamadı" in record or "Hata:" in record or "mevcut değil" in record:
                 print(Fore.YELLOW + f"  {record}" + Fore.RESET)
            else:
                 print(Fore.GREEN + f"  {record}" + Fore.RESET)
            
        # Email Spoofing (Phishing) testi: Sadece TXT kayıtlarında mantıklıdır.
        if record_type == "TXT" and "Kayıt bulunamadı" not in records[0]:
            check_email_spoofing(records)


def arg_parser():
    parser = argparse.ArgumentParser(
        description="DNSniper - Profesyonel DNS Bilgi Toplama ve Zafiyet Analiz Aracı",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Pentest Tavsiyeleri:
--------------------
• Bulduğunuz IP'leri 'Nmap' ile taramak için A kayıtlarını kullanın.
• --axfr opsiyonunu her testte mutlaka ekleyin. (Misconfiguration tespiti)
• MX sunucularında açık portları (25, 110, 143, vs.) denetleyebilirsiniz.
• Farklı DNS resolver (Örn: -n 1.1.1.1) ile hedefi sorgulayıp, 
  lokal sızıntı/waf atlatması deneyebilirsiniz.
        
Örnek Kullanım:
  python dnspider.py -d ornek-hedef.com
  python dnspider.py -d ornek-hedef.com --axfr
  python dnspider.py -d ornek-hedef.com -n 8.8.8.8 -o dnssonuc.txt
"""
    )
    
    parser.add_argument("-d", "--domain", help="Hedef Domain (örn: example.com)")
    parser.add_argument("-n", "--nameserver", help="Kullanılacak özel DNS sunucusu (ip adresi, örn: 8.8.8.8)")
    parser.add_argument("-o", "--output", help="Sonuçları belitilen dosyaya (.txt) kaydet")
    parser.add_argument("--axfr", action="store_true", help="Zone Transfer (AXFR) Zafiyet testini aktif et")
    
    return parser

def main():
    clear_screen()
    print_banner()
    
    parser = arg_parser()
    
    # Kullanıcı parametresiz ("python dnspider.py") çalıştırırsa help logla ve interaktif sor:
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        print("\n" + Fore.YELLOW + "[!] Argüman kullanılmadı, İnteraktif Moda geçiliyor..." + Fore.RESET)
        try:
            domain = input(Fore.MAGENTA + "Sorgulanacak domaini girin (örn. example.com): " + Fore.RESET).strip()
            if not domain:
                sys.exit(0)
            
            results = resolve_dns_records(domain)
            print_results(domain, results)
            
            # Otomatik AXFR sorma deneyimi (İnteraktif Mod için)
            if results.get("NS") and "Kayıt bulunamadı" not in results["NS"][0] and "Hata:" not in results["NS"][0]:
                ans = input(Fore.YELLOW + "\n[?] Kritik: Zone Transfer (AXFR) zafiyet testi yapılsın mı? (E/h): " + Fore.RESET).strip().lower()
                if ans in ['e', 'evet', 'y', 'yes', '']:
                    # nameserver kayıtlarından ns listesini çıkar, sonundaki root domain noktasını sil
                    ns_list = [ns.strip().rstrip('.') for ns in results["NS"]]
                    perform_zone_transfer(domain, ns_list)
                    
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] İşlem kullanıcı tarafından iptal edildi.")
        sys.exit(0)

    # Argümanlar işleniyor
    args = parser.parse_args()
    
    if not args.domain:
        print(Fore.RED + "[-] Lütfen bir domain belirtin (-d veya --domain)")
        sys.exit(1)
        
    print(Fore.MAGENTA + "[*] Analiz başlatılıyor..." + Fore.RESET)
    
    results = resolve_dns_records(args.domain, args.nameserver)
    print_results(args.domain, results)
    
    if args.axfr:
        if results.get("NS") and "Kayıt bulunamadı" not in results["NS"][0] and "Hata:" not in results["NS"][0]:
             ns_list = [ns.strip().rstrip('.') for ns in results["NS"]]
             perform_zone_transfer(args.domain, ns_list)
        else:
             print(Fore.RED + "\n[-] NS (Nameserver) kaydı bulunamadığından Zone Transfer testi atlanıyor.")
            
    if args.output:
        save_results(args.domain, results, args.output)
        print(Fore.GREEN + Style.BRIGHT + f"\n[+] Tüm sonuçlar başarıyla kaydedildi: {args.output}")

if __name__ == "__main__":
    main()
