import click
import json
from hackit.cve.go_bridge import GoEngine
from hackit.ui import _colored, BLUE, CYAN, YELLOW, RESET, MAGENTA

def _show_cve_banner():
    banner = f"""{CYAN}
       _____     _______   _____                                
      / ___/| | / / ____/  / ___/_________ _____  ____  ___  ____
     / /   | | / / __/     \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
    / /___ | |/ / /___    ___/ / /__/ /_/ / / / / / / /  __/ /    
    \____/ |___/_____/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
    {RESET}{BLUE}
    [+] Professional Defensive Vulnerability & Exposure Scanner [+]
    {RESET}
    {MAGENTA} "Knowing your vulnerabilities is the first step to true defense.
     Intelligence-driven security saves networks."{RESET}
    """
    click.echo(banner)

@click.command(name='cve')
@click.option('--output', help='Simpan hasil pencarian ke file JSON')
@click.option('--api-key', help='NVD API key (untuk rate limit lebih tinggi)')
@click.option('--max-results', type=int, default=20, help='Max CVEs per teknologi/scan')
def check_cve(output, api_key, max_results):
    """
    Pemindai Kerentanan Defensif (Multi-Source Intelligence).
    Mendeteksi teknologi dan memetakan skor CVE, CWE, OSV, CISA, OWASP, dan Exploit-DB.
    """
    _show_cve_banner()
    
    click.secho("[ Pilih Mode Pemindaian ]", fg='yellow', bold=True)
    click.echo("  [1] Parameter Link (WAF & Logic Scanning)")
    click.echo("  [2] Main URL (Deep Port & Tech Scanning)")
    
    mode_choice = input(f"\n{YELLOW}Pilih [1/2]: {RESET}").strip()
    mode_str = "parameter" if mode_choice == "1" else "main"
    
    target = input(f"{YELLOW}Input URL Target [Http/Https/IP] : {RESET}").strip()
        
    if not target:
        click.secho("[!] Target tidak boleh kosong.", fg='red', bold=True)
        return

    click.secho(f"\n[*] Menginisialisasi Mesin Deteksi & Analisis Kerentanan untuk {target} (Mode: {mode_str})...", fg='cyan', bold=True)
    engine = GoEngine()
    
    success = engine.run(
        target=target,
        mode=mode_str,
        output=output,
        api_key=api_key,
        max_results=max_results
    )
    
    if not success:
        click.secho("\n[!] Proses pemindaian kerentanan gagal atau dibatalkan.", fg='red', bold=True)
