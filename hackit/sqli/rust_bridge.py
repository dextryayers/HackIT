"""
Rust SQLi Engine Bridge — Direct ctypes integration with librust_engine.so
Provides HTTP request sending and blind SQLi char extraction via Rust FFI.
"""
import ctypes
import json
import os
import platform
from typing import Optional, Dict, Any

_lib: Optional[ctypes.CDLL] = None


def _load_lib():
    global _lib
    if _lib is not None:
        return _lib

    base = os.path.dirname(os.path.abspath(__file__))
    rust_dir = os.path.join(base, 'go', 'rust_engine', 'target', 'release')
    
    ext = '.dll' if platform.system() == 'Windows' else '.so'
    lib_path = os.path.join(rust_dir, f'librust_engine{ext}')
    
    if not os.path.exists(lib_path):
        # Try debug build
        rust_dir = os.path.join(base, 'go', 'rust_engine', 'target', 'debug')
        lib_path = os.path.join(rust_dir, f'librust_engine{ext}')
    
    if not os.path.exists(lib_path):
        return None

    try:
        _lib = ctypes.CDLL(lib_path)
        
        # rust_sqli_send_request(url, method, payload, timeout) -> c_char_p
        _lib.rust_sqli_send_request.restype = ctypes.c_char_p
        _lib.rust_sqli_send_request.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64
        ]
        
        # rust_blind_extract_char(url, template, position) -> c_char_p
        _lib.rust_blind_extract_char.restype = ctypes.c_char_p
        _lib.rust_blind_extract_char.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int32
        ]
        
        # rust_free_string(s) -> None
        _lib.rust_free_string.restype = None
        _lib.rust_free_string.argtypes = [ctypes.c_void_p]
        
        return _lib
    except Exception:
        _lib = None
        return None


def _call_and_free(func, *args) -> Optional[str]:
    lib = _load_lib()
    if lib is None:
        return None
    try:
        ptr = func(*args)
        if ptr is None:
            return None
        result = ctypes.cast(ptr, ctypes.c_char_p).value
        if result is not None:
            result = result.decode('utf-8')
        lib.rust_free_string(ptr)
        return result
    except Exception:
        return None


class RustEngine:
    """Rust-based SQLi engine. Lighter than Go engine — good for fast scanning."""
    
    def __init__(self):
        self._available = _load_lib() is not None
    
    @property
    def available(self) -> bool:
        return self._available
    
    def send_request(self, url: str, method: str = "GET", payload: str = "",
                     timeout: int = 10) -> Optional[Dict[str, Any]]:
        """Send HTTP request via Rust. Returns JSON dict with status/time_ms/len."""
        result = _call_and_free(
            _lib.rust_sqli_send_request,
            url.encode('utf-8'),
            method.encode('utf-8'),
            payload.encode('utf-8'),
            ctypes.c_uint64(timeout * 1000),
        )
        if result:
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return {"raw": result}
        return None
    
    def blind_extract_char(self, url: str, template: str, position: int) -> Optional[Dict[str, Any]]:
        """Extract a single character via binary search blind injection."""
        result = _call_and_free(
            _lib.rust_blind_extract_char,
            url.encode('utf-8'),
            template.encode('utf-8'),
            ctypes.c_int32(position),
        )
        if result:
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return {"raw": result}
        return None
    
    def scan(self, url: str, method: str = "GET", timeout: int = 10) -> Optional[Dict[str, Any]]:
        """Quick scan: just send a request and return response metadata."""
        return self.send_request(url, method, "", timeout)


if __name__ == "__main__":
    # Quick test
    eng = RustEngine()
    print(f"Rust Engine available: {eng.available}")
    if eng.available:
        result = eng.send_request("http://example.com/?id=1", payload="' AND 1=1--")
        print(f"Test request: {result}")
