"""
Dedicated OSINT banner.
"""

from __future__ import annotations

import click

from hackit.ui import _colored, B_CYAN, B_GREEN, B_MAGENTA, B_WHITE, DIM, WHITE, YELLOW


OSINT_ART = r"""
        __  __           __   ________   ____  _____ _____   ______
       / / / /___ ______/ /__/  _/ __/  / __ \/ ___//  _/ | / / __/
      / /_/ / __ `/ ___/ // // // /_   / / / /\__ \ / //  |/ / /_  
     / __  / /_/ / /__/ ,< _/ // __/  / /_/ /___/ // // /|  / __/  
    /_/ /_/\__,_/\___/_/|_/___/_/     \____//____/___/_/ |_/_/     

        PUBLIC IDENTITY RECON  |  SOCIAL FOOTPRINT  |  TRACE MATRIX
"""


def display_osint_banner() -> None:
    click.echo()
    click.echo(_colored(OSINT_ART, B_CYAN, bold=True))
    click.echo(_colored("  +--------------------------------------------------------------------------+", B_MAGENTA))
    click.echo(
        _colored("  | ", B_MAGENTA)
        + _colored("HACKIT OSINT INTELLIGENCE CONSOLE", B_WHITE, bold=True)
        + _colored(" :: ", DIM)
        + _colored("GLOBAL PUBLIC PROFILE CORRELATOR", YELLOW, bold=True)
        + " " * 5
        + _colored("|", B_MAGENTA)
    )
    click.echo(_colored("  +--------------------------------------------------------------------------+", B_MAGENTA))
    click.echo(
        "  "
        + _colored("[INPUT]", B_GREEN, bold=True)
        + _colored(" name / username / email  ", WHITE)
        + _colored("[OUTPUT]", B_GREEN, bold=True)
        + _colored(" live hits, misses, email signals, trace leads", WHITE)
    )
    click.echo(_colored("  " + "-" * 76, DIM))
    click.echo()
