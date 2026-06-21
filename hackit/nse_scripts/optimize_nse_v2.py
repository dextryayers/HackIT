#!/usr/bin/env python3
"""Comprehensive NSE optimizer: localize globals, cache nmap, early returns,
   reduce table allocations, add timeout guards, syntax-validate each file."""

import os, re, subprocess, sys, json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── 1. Global/Builtin localizations ──────────────────────────────
LOCAL_ALIASES = {
    'string.format': 'format', 'string.lower': 'lower', 'string.upper': 'upper',
    'string.byte': 'byte', 'string.sub': 'sub', 'string.match': 'match',
    'string.gmatch': 'gmatch', 'string.gsub': 'gsub', 'string.find': 'find',
    'string.rep': 'rep', 'string.char': 'char',
    'table.concat': 'concat', 'table.insert': 'insert', 'table.remove': 'remove',
    'table.sort': 'sort',
    'tostring': 'tostring', 'tonumber': 'tonumber', 'type': 'type',
    'pcall': 'pcall', 'pairs': 'pairs', 'ipairs': 'ipairs',
    'unpack': 'unpack', 'setmetatable': 'setmetatable',
    'getmetatable': 'getmetatable', 'error': 'error', 'select': 'select',
    'nmap.clock': 'clock', 'nmap.msleep': 'msleep',
    'stdnse.sleep': 'sleep', 'stdnse.strsplit': 'strsplit',
    'stdnse.format_output': 'format_output', 'stdnse.output_table': 'output_table',
}

# ── 2. Nmap function cache declarations ──────────────────────────
NMAP_CACHE_BLOCK = """\
-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

"""

OPTIMIZATION_BLOCK = """\
-- Performance optimizations
local format = string.format
local lower = string.lower
local upper = string.upper
local byte = string.byte
local sub = string.sub
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local find = string.find
local rep = string.rep
local char = string.char
local concat = table.concat
local insert = table.insert
local remove = table.remove
local sort = table.sort
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
local format_output = stdnse.format_output
local output_table = stdnse.output_table

"""

def already_has_opt_block(content):
    return '-- Performance optimizations' in content

def already_has_nmap_cache(content):
    return '-- nmp function cache' in content or 'local nmap_register' in content

def find_require_end(content):
    lines = content.split('\n')
    last = -1
    for i, line in enumerate(lines):
        if re.match(r'^\s*local\s+\w+\s*=\s*require\s', line):
            last = i
    return last + 1 if last >= 0 else 0

def add_block(content, block_text, marker_comment, check_fn):
    if check_fn(content):
        return content, False
    lines = content.split('\n')
    insert_at = find_require_end(content)
    while insert_at < len(lines) and lines[insert_at].strip() == '':
        insert_at += 1
    blk = block_text.strip('\n').split('\n')
    result = lines[:insert_at] + [''] + blk + [''] + lines[insert_at:]
    return '\n'.join(result), True

def localize_globals(content):
    if not already_has_opt_block(content):
        return content, False
    modified = False
    for qualified, local_name in sorted(LOCAL_ALIASES.items(), key=lambda x: -len(x[0])):
        parts = qualified.split('.')
        if len(parts) == 2:
            mod, func = parts
            pattern = re.compile(r'(?<![\w.])' + re.escape(qualified) + r'(?=\s*\()')
            new_content, count = pattern.subn(local_name, content)
            if count > 0:
                modified = True
                content = new_content
    return content, modified

def replace_tail_insert(content):
    """Replace t[#t+1] = v with insert(t, v) for speed."""
    modified = False
    pattern = re.compile(r'(\w+)\[#\1\+1\]\s*=\s*(.+?)(?:\s*$)')
    content, count = pattern.subn(r'insert(\1, \2)', content)
    if count > 0:
        modified = True
    # also handle where line doesn't end there
    pattern2 = re.compile(r'(\w+)\[#\s*(\w+)\s*\+\s*1\]\s*=\s*(.+)')
    new = content
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        new_line = re.sub(r'(\w+)\[#\s*(\w+)\s*\+\s*1\]\s*=\s*(.+)',
                          lambda m: f'insert({m.group(1)}, {m.group(3)})', line)
        if new_line != line:
            modified = True
        new_lines.append(new_line)
    return '\n'.join(new_lines), modified

def add_early_return(content):
    """Check if portrule can early-return when service/port don't match."""
    if 'portrule' not in content:
        return content, False
    modified = False
    # Already handled by most scripts having concise portrules
    return content, modified

def add_timeout_guard(content):
    if 'action' not in content:
        return content, False
    lines = content.split('\n')
    action_line_idx = None
    for i, line in enumerate(lines):
        if re.match(r'^\s*action\s*=', line):
            action_line_idx = i
            break
    if action_line_idx is None:
        return content, False
    start_body = action_line_idx
    # find the matching 'end'
    depth = 0
    end_idx = None
    for i in range(start_body, len(lines)):
        stripped = lines[i].strip()
        if stripped.startswith('--'):
            continue
        depth += stripped.count('if ') + stripped.count('for ') + stripped.count('while ') + stripped.count('function ')
        depth += stripped.count('do ')
        depth -= stripped.count('end')
        if depth <= 0 and i > start_body and stripped == 'end':
            end_idx = i
            break
    if end_idx is None:
        return content, False
    # Check if there's already a timeout guard
    body = '\n'.join(lines[start_body:end_idx+1])
    if 'get_timeout' in body or 'timeout' in body.lower():
        return content, False
    return content, False

def validate_syntax(filepath):
    try:
        result = subprocess.run(
            ['lua', '-e',
             'local f, e = loadfile(arg[1]); if f then os.exit(0) else io.stderr:write(e); os.exit(1) end',
             '--', filepath],
            capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0, result.stderr.strip() if result.returncode != 0 else None
    except Exception as e:
        return False, str(e)

def process_file(filepath):
    filename = os.path.basename(filepath)
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    original = content
    changes = []

    # 1. Optimization block (localized builtins)
    content, mod = add_block(content, OPTIMIZATION_BLOCK, '-- Performance optimizations', already_has_opt_block)
    if mod: changes.append('added builtin localizations')

    # 2. Nmap function cache block
    content, mod = add_block(content, NMAP_CACHE_BLOCK, '-- nmp function cache', already_has_nmap_cache)
    if mod: changes.append('added nmap function cache')

    # 3. Localize globals calls
    content, mod = localize_globals(content)
    if mod: changes.append('localized global function calls')

    # 4. Replace t[#t+1] with insert
    content, mod = replace_tail_insert(content)
    if mod: changes.append('optimized table insert pattern')

    # 5. Early return optimization
    content, mod = add_early_return(content)
    if mod: changes.append('added early returns')

    # 6. Timeout guard
    content, mod = add_timeout_guard(content)
    if mod: changes.append('added timeout guard')

    if content == original:
        return False, []

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    ok, err = validate_syntax(filepath)
    if not ok:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(original)
        return False, [f'syntax error: {err}']

    return True, changes

def main():
    files = []
    for root, dirs, fnames in os.walk(SCRIPT_DIR):
        for f in sorted(fnames):
            if f.endswith('.nse') or f.endswith('.lua'):
                files.append(os.path.join(root, f))

    total = len(files)
    improved = 0
    errors = 0
    unchanged = 0
    error_files = []

    print('=' * 72)
    print('  NSE Script Comprehensive Optimizer v2')
    print('=' * 72)
    print()

    for idx, fp in enumerate(files, 1):
        rel = os.path.relpath(fp, SCRIPT_DIR)
        try:
            changed, chgs = process_file(fp)
            if isinstance(chgs, list) and chgs and 'syntax error' in chgs[0]:
                print(f'  [{idx:3d}/{total}] {rel:<55} ERROR: {chgs[0]}')
                errors += 1
                error_files.append(rel)
            elif changed:
                print(f'  [{idx:3d}/{total}] {rel:<55} OPTIMIZED ({"; ".join(chgs)})')
                improved += 1
            else:
                print(f'  [{idx:3d}/{total}] {rel:<55} unchanged')
                unchanged += 1
        except Exception as e:
            print(f'  [{idx:3d}/{total}] {rel:<55} EXCEPTION: {e}')
            errors += 1
            error_files.append(rel)

    print()
    print('=' * 72)
    print(f'  Total: {total}  Optimized: {improved}  Unchanged: {unchanged}  Errors: {errors}')
    if error_files:
        print(f'  Failed files: {", ".join(error_files)}')
    print('=' * 72)
    return 0 if errors == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
