def display_osint_banner() -> None:
    import click
    from hackit.ui import _colored, B_CYAN, B_GREEN, DIM, WHITE

    click.echo()
    click.echo(_colored("""  ╔══════════════════════════════════════════════════╗""", B_CYAN))
    click.echo(_colored("""  ║              HACKIT OSINT ENGINE v3.0            ║""", B_CYAN))
    click.echo(_colored("""  ║        500+ Platforms · No API Required          ║""", B_CYAN))
    click.echo(_colored("""  ║    Email · Phone · Domain · Metadata · History   ║""", B_CYAN))
    click.echo(_colored("""  ╚══════════════════════════════════════════════════╝""", B_CYAN))
    click.echo()
