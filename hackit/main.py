import sys
import os

# Menambahkan parent directory ke sys.path agar hackit module bisa ditemukan
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from hackit.cli import cli

if __name__ == "__main__":
    cli()
