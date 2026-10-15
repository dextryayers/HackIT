def display_osint_banner() -> None:
    import click
    from hackit.ui import _colored, B_CYAN, B_GREEN, B_MAGENTA, B_WHITE, DIM

    try:
        from hackit.osint.sources import get_social_sources, SEARCH_LEADS
        n_src = len(get_social_sources())
        n_leads = len(SEARCH_LEADS)
    except Exception:
        n_src, n_leads = 800, 90

    art = r"""
   ____  _____ ___ _   _______
  / __ \/ ___//  _// | / /_  /
 / / / /\__ \ / / /  |/ / / /_
/ /_/ /___/ // / / /|  / / __/
\____//____/___//_/ |_/ /____/
    """
    click.echo()
    click.echo(_colored(art, B_CYAN, bold=True))
    click.echo(_colored("   █ HACKIT OSINT ENGINE v2.1 █", B_MAGENTA, bold=True))
    click.echo(
        _colored(f"   ◈ {n_src}+ platforms", B_GREEN)
        + _colored("  ·  ", DIM)
        + _colored(f"{n_leads}+ dork leads", B_GREEN)
        + _colored("  ·  ", DIM)
        + _colored("concurrent sweep", B_CYAN)
        + _colored("  ·  ", DIM)
        + _colored("smart verdicts", B_WHITE)
    )
    click.echo(_colored("   ─⌁ email · phone · domain · metadata · personae ⌁─", DIM))
    click.echo()
