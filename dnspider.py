import dns.resolver
import os
from pyfiglet import Figlet
from colorama import init, Fore

init()

def clear_screen():
    os.system("clear")

def print_banner():
    f = Figlet(font='slant', width=100)
    print(Fore.MAGENTA + f.renderText('DNSniper'))
    print(Fore.RED + "      | - |  By : F3NR1R - Cyber Security | - |         \n" + Fore.RESET)

def resolve_dns_records(domain):
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [answer.to_text() for answer in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = ["No answer"]
        except dns.resolver.NXDOMAIN:
            results[record_type] = ["Domain does not exist"]
        except Exception as e:
            results[record_type] = [f"Error: {str(e)}"]

    return results

def print_results(domain, results):
    print(f"DNS Records for {domain}:")
    for record_type, records in results.items():
        print(Fore.BLUE + f"\n{record_type} Records:" + Fore.RESET)
        for record in records:
            print(Fore.GREEN + f"  {record}" + Fore.RESET)

if __name__ == "__main__":
    clear_screen()  # Ekranı temizler
    print_banner()  # Banner yazdırır
    domain = input("Enter the domain to resolve: ").strip()
    results = resolve_dns_records(domain)
    print_results(domain, results)
