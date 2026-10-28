"""SQL injection module entry point.

Run ``python -m hackit.sqli`` for the interactive shell or pass command line
arguments to use the normal Click interface.
"""

import sys

from . import interactive_shell, test_sqli


def main() -> None:
    if len(sys.argv) > 1:
        test_sqli()
    else:
        interactive_shell()


if __name__ == "__main__":
    main()
