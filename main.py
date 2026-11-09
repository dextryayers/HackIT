#!/usr/bin/env python3
"""
HackIt main entry point — thin wrapper around hackit.boot.

The welcome/boot animation used to live here; it now lives in hackit/boot.py
so the console_scripts entry point (`hackit`, defined in setup.py) can run the
same sequence. `python3 main.py` keeps working exactly as before.
"""
from hackit.boot import cli_entry, welcome_animation  # noqa: F401

if __name__ == '__main__':
    cli_entry()
