"""
Global configuration helpers for HackIt.

Reads environment variables set by the CLI group or user.
"""
import os
try:
    from fake_useragent import UserAgent
    _ua = UserAgent()
except ImportError:
    _ua = None

def get_random_user_agent() -> str:
    """Return a random User-Agent string."""
    if _ua:
        try:
            return _ua.random
        except Exception:
            pass
    return "HackIt/1.0.0 (Security Testing Tool)"


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

