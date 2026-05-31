from rich.console import Console
from rich.table import Table

console = Console()

class UIRenderer:
    @staticmethod
    def create_target_table():
        table = Table(title="Captured Wireframe Telemetry (Live)", title_style="bold cyan")
        table.add_column("BSSID (Source MAC)", justify="center", style="cyan", no_wrap=True)
        table.add_column("Event Type", style="magenta")
        table.add_column("Frame Parameter / SSID / EAPOL Step", style="bold yellow")
        table.add_column("Size (bytes)", justify="right", style="green")
        return table
        
    @staticmethod
    def print_warning(msg: str):
        console.print(f"[bold yellow][*] {msg}[/bold yellow]")
        
    @staticmethod
    def print_error(msg: str):
        console.print(f"[bold red][!] {msg}[/bold red]")
        
    @staticmethod
    def print_success(msg: str):
        console.print(f"[bold green][+] {msg}[/bold green]")
