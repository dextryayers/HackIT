#!/usr/bin/env python3
"""Deep expert transformation for all 306 NSE Lua scripts.

Converts string.method() → method(), var:method() → method(var, ...),
nmap.method() → cached_method(), and fixes syntax bugs.
"""

import re, os, glob, subprocess, sys

NSE_DIR = '/home/aniipid/HackIT/hackit/nse_scripts'

# String methods that are localized
STRING_METHODS = [
    'format', 'lower', 'upper', 'byte', 'sub', 'match',
    'gmatch', 'gsub', 'find', 'rep', 'char'
]

# Table methods that are localized
TABLE_METHODS = ['concat', 'insert', 'remove', 'sort']

# nmap functions that are cached
NMAP_CACHE = {
    'register_script': 'nmap_register',
    'set_title': 'nmap_settitle',
    'resolve': 'nmap_resolve',
    'get_port_state': 'nmap_get_port_state',
    'set_port_state': 'nmap_set_port_state',
    'comm': 'comm',
    'new_socket': 'new_socket',
    'get_timeout': 'get_timeout',
}

ALL_METHODS = STRING_METHODS + TABLE_METHODS


def find_matching_paren(s, start):
    """Find matching closing paren from opening paren at start."""
    count = 0
    for i in range(start, len(s)):
        if s[i] == '(':
            count += 1
        elif s[i] == ')':
            count -= 1
            if count == 0:
                return i
    return -1


def split_comment(line):
    """Split line into (code, comment). Simple, assumes -- is comment."""
    # Find -- not inside a string literal (simplified)
    in_single = False
    in_double = False
    for i in range(len(line)):
        ch = line[i]
        if ch == '"' and (i == 0 or line[i-1] != '\\'):
            in_double = not in_double
        elif ch == "'" and (i == 0 or line[i-1] != '\\'):
            in_single = not in_single
        elif ch == '-' and i + 1 < len(line) and line[i + 1] == '-':
            if not in_single and not in_double:
                return line[:i], line[i:]
    return line, ''


def transform_dot_calls(code):
    """Transform string.method(args) → method(args) and table.method(args) → method(args)."""
    for m in ALL_METHODS:
        code = re.sub(r'\bstring\.' + m + r'\s*\(', m + '(', code)
        if m in TABLE_METHODS:
            code = re.sub(r'\btable\.' + m + r'\s*\(', m + '(', code)
    return code


def transform_nmap_calls(code):
    """Transform nmap.method(args) → cached_method(args)."""
    for orig, cached in NMAP_CACHE.items():
        code = re.sub(r'\bnmap\.' + orig + r'\s*\(', cached + '(', code)
    return code


def transform_colon_to_func(code):
    """Transform var:method(args) → method(var, args) for all cached methods."""
    # Build pattern: WORD:method_name(
    # We handle this with a custom parser since we need to find matching paren
    result = []
    i = 0
    while i < len(code):
        # Check if we're inside a string
        # Look for WORD:METHOD( pattern
        best = None
        best_start = None
        best_end = None
        best_var = None
        best_m = None

        for m_name in ALL_METHODS:
            pat = re.compile(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*' + m_name + r'\s*\(')
            match = pat.search(code, i)
            if match:
                start = match.start()
                if best is None or start < best_start:
                    # Make sure this isn't a function definition (function var:method(…))
                    before = code[max(0, start - 20):start].strip()
                    if before.endswith('function') or before.endswith('function '):
                        # This is a method definition, skip
                        best = None
                        continue
                    best_start = start
                    best_end = match.end()
                    best_var = match.group(1)
                    best_m = m_name

        if best is None:
            result.append(code[i:])
            break

        # Find matching closing paren
        close = find_matching_paren(code, best_end - 1)
        if close < 0:
            result.append(code[i:])
            break

        var_name = best_var
        m_name = best_m
        args = code[best_end:close].strip()

        # Build replacement
        if args:
            replacement = f'{m_name}({var_name}, {args})'
        else:
            replacement = f'{m_name}({var_name})'

        result.append(code[i:best_start])
        result.append(replacement)
        i = close + 1

    return ''.join(result)


def transform_format_method(code):
    """Transform "fmt":format(args) → format("fmt", args)."""
    # Match string literals followed by :format(
    # Pattern: "..."  or  '...'  followed by :format(
    result = []
    i = 0
    while i < len(code):
        # Find opening quote
        m = re.search(r"""(["'])(?:[^\\]|\\.)*?\1\s*:\s*format\s*\(""", code[i:])
        if not m:
            result.append(code[i:])
            break

        start = i + m.start()
        end = i + m.end()  # position right after '('

        # Find the format string
        fmt_str = code[start:end - 1]  # includes the "..." and ":format("
        # Extract just the "..." part
        quote_char = fmt_str[0]
        # Find the closing quote
        fmt_end = 0
        for j in range(1, len(fmt_str)):
            if fmt_str[j] == quote_char and (j == 1 or fmt_str[j-1] != '\\'):
                fmt_end = j
                break
        if fmt_end == 0:
            result.append(code[i:start])
            i = start + 1
            continue

        str_literal = fmt_str[:fmt_end + 1]
        
        # Find matching closing paren for the whole :format(...) call
        close = find_matching_paren(code, end - 1)
        if close < 0:
            result.append(code[i:])
            break

        args = code[end:close].strip()

        if args:
            replacement = f'format({str_literal}, {args})'
        else:
            replacement = str_literal

        result.append(code[i:start])
        result.append(replacement)
        i = close + 1

    return ''.join(result)


def transform_file(filepath):
    with open(filepath) as f:
        content = f.read()

    original = content

    # Fix brute-ftp.nse syntax bug
    content = content.replace('insert(items, item end)', 'insert(items, item) end')

    lines = content.split('\n')
    new_lines = []
    for line in lines:
        code, comment = split_comment(line)
        if code.strip():
            code = transform_dot_calls(code)
            code = transform_nmap_calls(code)
            code = transform_colon_to_func(code)
            code = transform_format_method(code)
        new_lines.append(code + comment)

    content = '\n'.join(new_lines)

    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False


def validate_syntax(filepath):
    """Validate Lua syntax using luac -p or lua -p."""
    try:
        result = subprocess.run(
            ['luac', '-p', filepath],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return True, ''
        return False, result.stderr.strip()
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ['lua', '-p', filepath],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return True, ''
            return False, result.stderr.strip()
        except FileNotFoundError:
            return None, 'luac/lua not found'


def main():
    files = sorted(glob.glob(os.path.join(NSE_DIR, '*.nse')))
    print(f'Processing {len(files)} NSE scripts...')

    changed = 0
    errors = []
    for fp in files:
        try:
            if transform_file(fp):
                changed += 1
                print(f'  ✓ modified: {os.path.basename(fp)}')
        except Exception as e:
            errors.append((os.path.basename(fp), str(e)))
            print(f'  ✗ error: {os.path.basename(fp)}: {e}')

    print(f'\nModified: {changed} files')
    if errors:
        print(f'Errors: {len(errors)}')
        for f, e in errors[:10]:
            print(f'  {f}: {e}')

    # Validate syntax
    print('\nValidating syntax...')
    valid = 0
    invalid = []
    skipped = 0
    for fp in files:
        status, err = validate_syntax(fp)
        if status is None:
            skipped += 1
        elif status:
            valid += 1
        else:
            invalid.append((os.path.basename(fp), err))

    print(f'Syntax OK: {valid}, Failed: {len(invalid)}, Skipped (no checker): {skipped}')
    for f, e in invalid[:5]:
        print(f'  ✗ {f}: {e[:120]}')


if __name__ == '__main__':
    main()
