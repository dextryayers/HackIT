"""
Global configuration helpers for HackIt.

Reads environment variables set by the CLI group or user.
"""
import os


def get_proxy() -> str | None:
    """Return proxy URL from environment or None."""
    return os.environ.get('HACKIT_PROXY')


def verify_ssl_default() -> bool:
    """Return whether SSL verification should be enabled by default.

    Controlled via the `HACKIT_VERIFY` environment variable. If the value
    is missing or truthy, verification is enabled. If it's '0', 'false',
    or 'no', verification is disabled.
    """
    val = os.environ.get('HACKIT_VERIFY')
    if val is None:
        return True
    return val.lower() not in ('0', 'false', 'no')

