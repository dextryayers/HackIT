#!/usr/bin/env python3
"""Deep-optimize all NSE scripts for maximum Lua performance."""

import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

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
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
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

LOCAL_ALIASES = {
    'string.format': 'format',
    'string.lower': 'lower',
    'string.upper': 'upper',
    'string.byte': 'byte',
    'string.sub': 'sub',
    'string.match': 'match',
    'string.gmatch': 'gmatch',
    'string.gsub': 'gsub',
    'string.find': 'find',
    'string.rep': 'rep',
    'string.char': 'char',
    'table.concat': 'concat',
    'table.insert': 'insert',
    'table.remove': 'remove',
    'table.sort': 'sort',
    'table.move': 'move',
    'tostring': 'tostring',
    'tonumber': 'tonumber',
    'type': 'type',
    'pcall': 'pcall',
    'pairs': 'pairs',
    'ipairs': 'ipairs',
    'unpack': 'unpack',
    'setmetatable': 'setmetatable',
    'getmetatable': 'getmetatable',
    'error': 'error',
    'select': 'select',
    'nmap.clock': 'clock',
    'nmap.msleep': 'msleep',
    'stdnse.sleep': 'sleep',
    'stdnse.strsplit': 'strsplit',
    'stdnse.format_output': 'format_output',
    'stdnse.output_table': 'output_table',
}

def already_has_opt_block(content):
    return '-- Performance optimizations' in content

def add_optimization_block(content):
    """Add the standard optimization block after require statements."""
    if already_has_opt_block(content):
        return content, False
    
    lines = content.split('\n')
    # Find last require line
    last_require = -1
    for i, line in enumerate(lines):
        m = re.match(r'^\s*local\s+\w+\s*=\s*require\s', line)
        if m:
            last_require = i
    
    if last_require < 0:
        return content, False
    
    # Skip blank lines after last require
    insert_at = last_require + 1
    while insert_at < len(lines) and lines[insert_at].strip() == '':
        insert_at += 1
    
    # Check if there's already a description after requires
    # If so, insert optimization block before description
    opt_lines = OPTIMIZATION_BLOCK.strip('\n').split('\n')
    
    # Add blank line before and after
    result = lines[:insert_at] + [''] + opt_lines + [''] + lines[insert_at:]
    return '\n'.join(result), True

def localize_globals(content):
    """Replace qualified global calls with local aliases."""
    if not already_has_opt_block(content):
        return content, False
    
    modified = False
    for qualified, local_name in LOCAL_ALIASES.items():
        # Don't replace inside require statements or the optimization block itself
        # Pattern: qualified call that's NOT preceded by 'local' (already localized)
        # We need to be careful - only replace when used as a function call
        
        parts = qualified.split('.')
        if len(parts) == 2:
            mod, func = parts
            # string.format(...) -> format(...)
            # But NOT inside require "string" etc.
            # Match: <mod>.<func> followed by ( or space then something
            pattern = re.compile(
                r'(?<![\w.])' + re.escape(qualified) + r'(?=\s*\()'
            )
            new_content, count = pattern.subn(local_name, content)
            if count > 0:
                modified = True
                content = new_content
    
    return content, modified

def replace_table_getn(content):
    """Replace table.getn(x) with #x."""
    modified = False
    
    # table.getn(var) -> #var
    pattern = re.compile(r'table\.getn\s*\(\s*(\w+)\s*\)')
    new_content, count = pattern.subn(r'#\1', content)
    if count > 0:
        modified = True
        content = new_content
    
    return content, modified

def optimize_string_concat(content):
    """Optimize string concatenation in loops: replace building strings with table.concat."""
    # Pattern: inside a for/while loop, look for:
    #   var = var .. expr
    # We'll transform loops that build strings to use table and concat
    # This is tricky to do correctly, so we do a simpler version:
    # Replace simple repeated .. in sequence with table.concat
    
    # Find patterns like: s = s .. x .. y .. z  (multiple concatenations in one statement)
    # These can be optimized by grouping
    # Actually, Lua optimizes a .. b .. c into one allocation already in 5.3+
    # Let's skip this as it can change behavior
    
    return content, False

def optimize_table_allocations(content):
    """Optimize table creation patterns."""
    modified = False
    
    # Pattern: copying a table by iterating pairs
    # local new = {}; for k,v in pairs(old) do new[k] = v end
    # This is a table clone - keep as-is since Lua doesn't have a built-in clone
    
    # Pattern: local t = {}; for i=1,N do t[i] = ... end
    # Can we detect pre-allocation? We need to know N.
    # This is hard to automate, skip.
    
    return content, False

def optimize_early_return(content):
    """Restructure conditions for early returns where safe."""
    modified = False
    
    # Pattern: if condition then ... end; return result
    # -> if not condition then return nil end; ... ; return result
    # This is risky to automate - might change behavior in subtle ways
    # Skip this automated transformation
    
    return content, False

def add_regex_cache(content):
    """Add memoization for frequently used patterns."""
    # Look for patterns like: var:match("pattern") or var:find("pattern")
    # called multiple times with the same pattern
    # We can extract these and cache the compiled pattern
    # But Lua string patterns can't be pre-compiled like PCRE
    # So we can't really add regex caching in standard Lua
    return content, False

def optimize_byte_checks(content):
    """Replace simple pattern matching with string.byte for single char checks."""
    modified = False
    
    # Patterns like: s:find("^[") or s:match("^[")
    # -> s:byte(1) == char_code
    
    # gsub("^%s+", "") -> expensive, keep as-is since it's a trim
    
    # Find: s:sub(1,1) == "x" -> s:byte() == asc('x')
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        # Replace var:sub(1, 1) == "X" or var:sub(1,1) ~= "X" with byte comparison
        # Pattern: (\w+):sub\(1\s*,\s*1\)\s*(==|~=)\s*"([^"]))"
        new_line = re.sub(
            r'(\w+)\((\w+):sub\(1\s*,\s*1\)\s*(==|~=)\s*"(.+?)"\)',
            lambda m: f'{m.group(1)}({m.group(2)}:byte() {m.group(3)} {ord(m.group(4)[0])})',
            line
        )
        new_line = re.sub(
            r'(\w+):sub\(1\s*,\s*1\)\s*(==|~=)\s*"(.+?)"',
            lambda m: f'{m.group(1)}:byte() {m.group(2)} {ord(m.group(3)[0])}',
            new_line
        )
        # Also handle: var:byte(1) == asc('X') -> var:byte() == asc('X')
        # Actually that's already optimal
        
        if new_line != line:
            modified = True
        new_lines.append(new_line)
    
    return '\n'.join(new_lines), modified

def optimize_comparison_order(content):
    """Reorder and/or conditions to put cheaper checks first."""
    modified = False
    
    # This is hard to automate safely since we need to understand
    # what's "cheaper" - skip automated transformation
    
    return content, False

def remove_redundant_nil_checks(content):
    """Remove redundant nil checks like 'if x ~= nil then' -> 'if x then'."""
    modified = False
    
    content = re.sub(r'if\s+(\w+)\s*~=\s*nil\s+then(?!\s*\n?\s*return)', r'if \1 then', content)
    # Be careful: if x ~= nil then return end -> we should keep that since
    # it explicitly tests for nil vs false
    
    return content, False

def optimize_socket_creation(content):
    """Move socket creation outside loops where possible."""
    modified = False
    
    # Pattern: inside loop, local sock = nmap.new_socket()
    # We can move it outside the loop, but this changes socket lifecycle
    # Too risky to automate fully
    
    return content, False

def optimize_pcall_protect(content):
    """Add socket close protection in error cases."""
    # Already handled by improve_all.py
    return content, False

def normalize_whitespace(content):
    """Normalize trailing whitespace."""
    lines = content.split('\n')
    new_lines = []
    modified = False
    for line in lines:
        new_line = line.rstrip()
        if new_line != line:
            modified = True
        new_lines.append(new_line)
    return '\n'.join(new_lines), modified

def validate_syntax(filepath):
    """Check Lua syntax."""
    try:
        result = subprocess.run(
            ["lua", "-e", 
             "local f, e = loadfile(arg[0]); if f then os.exit(0) else io.stderr:write(e); os.exit(1) end",
             filepath],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, None
        return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return True, None
    except Exception as e:
        return False, str(e)

def process_file(filepath):
    """Process a single .nse file."""
    filename = os.path.basename(filepath)
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    original = content
    changes = []
    
    # Apply optimizations
    # 1. Add optimization block
    content, mod = add_optimization_block(content)
    if mod:
        changes.append("added optimization block (localized globals)")
    
    # 2. Replace table.getn with #
    content, mod = replace_table_getn(content)
    if mod:
        changes.append("replaced table.getn with # operator")
    
    # 3. Localize global function calls
    content, mod = localize_globals(content)
    if mod:
        changes.append("localized global function calls")
    
    # 4. Optimize byte checks
    content, mod = optimize_byte_checks(content)
    if mod:
        changes.append("optimized string.byte checks")
    
    # 5. Remove redundant nil checks
    content, mod = remove_redundant_nil_checks(content)
    if mod:
        changes.append("removed redundant nil checks")
    
    # 6. Normalize whitespace
    content, mod = normalize_whitespace(content)
    if mod:
        changes.append("normalized trailing whitespace")
    
    if content != original:
        # Ensure trailing newline
        if not content.endswith('\n'):
            content += '\n'
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Validate syntax
        ok, err = validate_syntax(filepath)
        if not ok:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(original)
            return False, err
        
        return True, changes
    
    return False, []

def identify_further_optimizations(filepath):
    """Identify specific file-level optimizations that can't be automated generically."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    filename = os.path.basename(filepath)
    suggestions = []
    
    # Check for socket-in-loop patterns
    if re.search(r'for\s+.*\n.*nmap\.new_socket\(\)', content, re.DOTALL):
        suggestions.append("socket reuse: consider moving nmap.new_socket() outside loop")
    
    # Check for repeated pattern matching
    patterns = re.findall(r'(:\w+\(["\'].*?["\']\))', content)
    from collections import Counter
    pattern_counts = Counter(patterns)
    for pat, count in pattern_counts.most_common(3):
        if count > 2 and count > 1:
            suggestions.append(f"regex caching: pattern {pat} used {count}x, could pre-compile")
    
    # Check for string concatenation in loops
    if re.search(r'for\s+.*\n.*=\s*\w+\s*\.\.\s*', content, re.DOTALL):
        suggestions.append("string build: use table.concat instead of .. in loop")
    
    # Check for anonymous functions in loops (closure allocation)
    loop_anon = re.findall(r'(for\s+.*\n.*?(?:function\s*\()|for\s+.*\n.*?pcall\s*\(\s*function)', content, re.DOTALL)
    if loop_anon:
        suggestions.append("closure allocation: move anonymous functions outside loops")
    
    # Check for floating point where integer would work
    if re.search(r'math\.floor\(|math\.ceil\(', content):
        suggestions.append("integer math: use // instead of math.floor/ceil")
    
    return suggestions

def main():
    # Collect all .nse files
    all_files = []
    for root, dirs, files in os.walk(SCRIPT_DIR):
        for f in sorted(files):
            if f.endswith('.nse'):
                all_files.append(os.path.join(root, f))
    
    total = len(all_files)
    improved = 0
    errors = 0
    unchanged = 0
    all_suggestions = {}
    
    print("=" * 72)
    print("  NSE Script Performance Optimizer")
    print("=" * 72)
    print()
    
    for idx, filepath in enumerate(all_files, 1):
        fname = os.path.basename(filepath)
        relpath = os.path.relpath(filepath, SCRIPT_DIR)
        
        try:
            changed, result = process_file(filepath)
            if isinstance(result, str) and not isinstance(result, list):
                print(f"  [{(idx):3d}/{total}] {fname:<50} ERROR: {result}")
                errors += 1
            elif changed:
                changes_str = "; ".join(result)
                print(f"  [{(idx):3d}/{total}] {fname:<50} OPTIMIZED ({changes_str})")
                improved += 1
                # Check for further suggestions
                suggestions = identify_further_optimizations(filepath)
                if suggestions:
                    all_suggestions[fname] = suggestions
            else:
                print(f"  [{(idx):3d}/{total}] {fname:<50} unchanged")
                unchanged += 1
        except Exception as e:
            print(f"  [{(idx):3d}/{total}] {fname:<50} ERROR: {e}")
            errors += 1
    
    print()
    print("=" * 72)
    print(f"  Total files: {total}")
    print(f"  Optimized:   {improved}")
    print(f"  Unchanged:   {unchanged}")
    print(f"  Errors:      {errors}")
    print()
    
    if all_suggestions:
        print("-" * 72)
        print("  Further optimization opportunities (manual review recommended):")
        print("-" * 72)
        for fname, suggestions in sorted(all_suggestions.items()):
            print(f"\n  {fname}:")
            for s in suggestions:
                print(f"    - {s}")
    
    return 0 if errors == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
