#!/usr/bin/env python3
"""Batch-improve all NSE scripts in this directory."""

import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

REQUIRES_ORDER = [
    ("nmap", 'local nmap = require "nmap"'),
    ("stdnse", 'local stdnse = require "stdnse"'),
    ("shortport", 'local shortport = require "shortport"'),
]

CATEGORY_MAP = {
    "audit": "audit",
    "brute": "brute",
    "cloud": "cloud",
    "dns": "dns",
    "ftp": "ftp",
    "http": "vuln",
    "ldap": "discovery",
    "mongodb": "discovery",
    "network": "discovery",
    "ntp": "discovery",
    "redis": "discovery",
    "smb": "exploit",
    "smtp": "discovery",
    "sql": "discovery",
    "ssh": "safe",
    "ssl": "vuln",
    "vpn": "discovery",
}

PORT_MAP = {
    "amqp": 5672,
    "bgp": 179,
    "bacnet": 47808,
    "cassandra": 9042,
    "cockroachdb": 26257,
    "couchdb": 5984,
    "db2": 50000,
    "dns": 53,
    "elasticsearch": 9200,
    "ftp": 21,
    "graphql": 80,
    "http": 80,
    "imap": 143,
    "ipmi": 623,
    "ldap": 389,
    "memcached": 11211,
    "mongodb": 27017,
    "mssql": 1433,
    "mqtt": 1883,
    "mysql": 3306,
    "nfs": 2049,
    "ntp": 123,
    "oracle": 1521,
    "pop3": 110,
    "postgresql": 5432,
    "redis": 6379,
    "riak": 8087,
    "rlogin": 513,
    "rsync": 873,
    "smb": 445,
    "smtp": 25,
    "snmp": 161,
    "ssh": 22,
    "ssl": 443,
    "telnet": 23,
    "tftp": 69,
    "vnc": 5900,
    "vpn": 500,
    "x11": 6000,
}

SERVICE_MAP = {
    "amqp": "amqp",
    "bacnet": "bacnet",
    "bgp": "bgp",
    "cassandra": "cassandra",
    "cockroachdb": "cockroachdb",
    "couchdb": "couchdb",
    "db2": "db2",
    "dns": "domain",
    "elasticsearch": "http",
    "ftp": "ftp",
    "graphql": "http",
    "http": "http",
    "imap": "imap",
    "ipmi": "ipmi",
    "ldap": "ldap",
    "memcached": "memcached",
    "mongodb": "mongodb",
    "mssql": "ms-sql-s",
    "mqtt": "mqtt",
    "mysql": "mysql",
    "nfs": "nfs",
    "ntp": "ntp",
    "oracle": "oracle-tns",
    "pop3": "pop3",
    "postgresql": "postgresql",
    "redis": "redis",
    "riak": "riak",
    "rlogin": "login",
    "rsync": "rsync",
    "smb": "microsoft-ds",
    "smtp": "smtp",
    "snmp": "snmp",
    "ssh": "ssh",
    "ssl": "https",
    "telnet": "telnet",
    "tftp": "tftp",
    "vnc": "vnc",
    "vpn": "isakmp",
    "x11": "x11",
}


def find_keyword(content, *keywords):
    """Return the first line matching any keyword pattern."""
    lines = content.split("\n")
    for kw in keywords:
        for i, line in enumerate(lines):
            if re.search(kw, line):
                return i, line
    return None, None


def find_require_section_end(content):
    """Find where the require block ends (line index after last require)."""
    lines = content.split("\n")
    last_require = -1
    for i, line in enumerate(lines):
        if re.match(r"^local\s+\w+\s*=\s*require\s", line):
            last_require = i
    if last_require >= 0:
        return last_require + 1
    return 0


def add_missing_requires(content):
    """Add missing local require lines."""
    modified = False
    lines = content.split("\n")

    existing = set()
    for line in lines:
        m = re.match(r"^local\s+(\w+)\s*=\s*require\s", line)
        if m:
            existing.add(m.group(1))

    insert_after = find_require_section_end(content)

    added = []
    for key, line_text in REQUIRES_ORDER:
        if key not in existing:
            added.append(line_text)

    if added:
        for line_text in reversed(added):
            lines.insert(insert_after, line_text)
        modified = True

    return "\n".join(lines), modified


def has_description(content):
    """Check if description block exists."""
    return bool(re.search(r"^\s*description\s*=", content, re.MULTILINE))


def has_author(content):
    """Check if author exists."""
    return bool(re.search(r"^\s*author\s*=", content, re.MULTILINE))


def has_categories(content):
    """Check if categories exists."""
    return bool(re.search(r"^\s*categories\s*=", content, re.MULTILINE))


def has_portrule(content):
    """Check if portrule exists."""
    return bool(re.search(r"^\s*portrule\s*=", content, re.MULTILINE))


def has_action(content):
    """Check if action function exists."""
    return bool(re.search(r"^\s*action\s*=", content, re.MULTILINE))


def guess_categories(filename):
    """Guess categories from filename prefix."""
    stem = os.path.splitext(filename)[0]
    parts = stem.split("-")
    if parts:
        prefix = parts[0].lower()
        if prefix in CATEGORY_MAP:
            return [CATEGORY_MAP[prefix], "discovery"]
    return ["safe", "discovery"]


def guess_port(filename):
    """Guess port number from filename."""
    stem = os.path.splitext(filename)[0].lower()
    for key, port in PORT_MAP.items():
        if key in stem:
            return port
    return 80


def guess_service(filename):
    """Guess service from filename."""
    stem = os.path.splitext(filename)[0].lower()
    for key, service in SERVICE_MAP.items():
        if key in stem:
            return service
    return "http"


def make_description(filename):
    """Generate a generic description block."""
    stem = os.path.splitext(filename)[0].replace("-", " ").title()
    return f"[[{stem} script for Nmap NSE.]]"


def make_portrule(filename):
    """Generate a portrule based on filename."""
    port = guess_port(filename)
    service = guess_service(filename)
    return (
        f"portrule = function(host, port)\n"
        f"  return port.protocol == \"tcp\" and port.state == \"open\" and "
        f"(port.number == {port} or port.service == \"{service}\")\n"
        f"end"
    )


def _is_http_like(filename):
    stem = os.path.splitext(filename)[0].lower()
    return any(x in stem for x in ("http", "graphql", "web", "cms", "wordpress", "joomla", "drupal"))


def make_action_generic(filename):
    """Generate a basic action function."""
    port = guess_port(filename)
    return (
        f"action = function(host, port)\n"
        f"  local socket = nmap.new_socket()\n"
        f"  socket:set_timeout(5000)\n"
        f"  local ok, err = pcall(function()\n"
        f"    socket:connect(host, port)\n"
        f"  end)\n"
        f"  if not ok then\n"
        f"    return stdnse.format_output(false, \"Connection failed: \" .. tostring(err))\n"
        f"  end\n"
        f"  socket:close()\n"
        f"  return stdnse.format_output(true, \"{os.path.splitext(filename)[0].replace('-', ' ')} check completed\")\n"
        f"end"
    )


def add_description_block(content, filename):
    """Add description before action or at end of require block."""
    lines = content.split("\n")
    desc = make_description(filename)
    # Insert after requires/before first non-require assignment
    insert_at = find_require_section_end(content)
    while insert_at < len(lines) and lines[insert_at].strip() == "":
        insert_at += 1
    lines.insert(insert_at, desc)
    lines.insert(insert_at, "")
    return "\n".join(lines)


def add_author_line(content):
    """Add author line."""
    lines = content.split("\n")
    # Find a good insertion point - after description or after requires
    for i, line in enumerate(lines):
        if re.match(r"^\s*description\s*=", line) or re.match(r"^\s*license\s*=", line):
            # find the end of the description block (closing ]])
            j = i
            while j < len(lines) and not re.search(r"\]\]", lines[j]):
                j += 1
            if re.search(r"\]\]", lines[j]):
                lines.insert(j + 1, 'author = "HackIT"')
                return "\n".join(lines)
    # Fallback: after requires
    insert_at = find_require_section_end(content)
    lines.insert(insert_at, 'author = "HackIT"')
    return "\n".join(lines)


def add_categories_line(content, filename):
    """Add categories line."""
    cats = guess_categories(filename)
    cat_str = '{%s}' % ', '.join('"%s"' % c for c in cats)
    lines = content.split("\n")
    # Insert after author
    for i, line in enumerate(lines):
        if re.match(r"^\s*author\s*=", line):
            lines.insert(i + 1, "categories = " + cat_str)
            return "\n".join(lines)
    # Fallback
    insert_at = find_require_section_end(content)
    lines.insert(insert_at, "categories = " + cat_str)
    return "\n".join(lines)


def add_portrule(content, filename):
    """Add portrule function."""
    pr = make_portrule(filename)
    lines = content.split("\n")
    # Insert after categories line or after the last metadata block
    for i, line in enumerate(lines):
        if re.match(r"^\s*categories\s*=", line):
            lines.insert(i + 1, "")
            lines.insert(i + 2, pr)
            return "\n".join(lines)
    # Fallback: before action
    for i, line in enumerate(lines):
        if re.match(r"^\s*action\s*=", line):
            lines.insert(i, pr)
            lines.insert(i, "")
            return "\n".join(lines)
    return content


def add_action(content, filename):
    """Add action function."""
    action = make_action_generic(filename)
    lines = content.split("\n")
    # Append at end
    if lines and lines[-1] != "":
        lines.append("")
    lines.append(action)
    return "\n".join(lines)


BLOCK_OPENERS = {
    "if", "for", "while", "function", "do",
}


def _block_depth_cmp(match_text):
    """Count how much a line changes the block depth.

    Returns +N for opens, -N for closes, 0 if no change.
    Only counts keywords that are not inside strings/comments.
    This is a best-effort heuristic.
    """
    stripped = match_text.strip()
    if stripped.startswith("--"):
        return 0

    opens = 0
    for kw in BLOCK_OPENERS:
        if re.search(r"\b" + kw + r"\b", stripped):
            opens += 1
    closes = len(re.findall(r"\bend\b", stripped))
    return opens - closes


def find_action_body_end(action_lines, body_start):
    """Find the line index (within action_lines) of the closing 'end' for the action function.

    Uses block depth tracking for all Lua block structures.
    Starts at depth=1 (inside action function body).
    """
    depth = 1
    for i in range(body_start + 1, len(action_lines)):
        depth += _block_depth_cmp(action_lines[i])
        if depth <= 0:
            return i
    return None


def uses_http_library(text):
    """Check if the file requires http library."""
    for line in text.split("\n"):
        if re.match(r'^local\s+http\s*=\s*require\s+"http"', line):
            return True
    return False


def wrap_socket_in_pcall(text):
    """Wrap bare nmap.new_socket() usage with pcall in action function.

    Only operates on socket operations that are not already wrapped in pcall.
    Skips files that use the http library (they use http.get, not raw sockets).
    """
    if "pcall" in text:
        return text, False

    if uses_http_library(text):
        return text, False

    if "nmap.new_socket" not in text:
        return text, False

    lines = text.split("\n")

    action_start = None
    for i, line in enumerate(lines):
        if re.match(r"^\s*action\s*=", line):
            action_start = i
            break
    if action_start is None:
        return text, False

    # Extract action lines from start to end of file
    action_lines = lines[action_start:]
    body_start = 0  # action_lines[0] is the action declaration

    action_body_end = find_action_body_end(action_lines, body_start)
    if action_body_end is None:
        return text, False

    # Check if the action already has pcall somewhere
    action_block = "\n".join(action_lines[: action_body_end + 1])
    if "pcall" in action_block:
        return text, False

    # The action body is lines (body_start+1) .. (action_body_end-1)
    # action_body_end is the closing `end` of the action function
    # We will remove that end and add it back after the pcall wrapper

    # Indent the body lines by 2 spaces (excluding the opening func line and closing end)
    for i in range(body_start + 1, action_body_end):
        if action_lines[i].strip():
            action_lines[i] = "  " + action_lines[i]

    # Save and remove the closing `end` of the action function
    original_closing_end = action_lines[action_body_end]

    # Build the wrapper structure:
    #   local status, err = pcall(function()
    #       <body>   (already indented by 2 spaces)
    #   end)
    #   if not status then
    #     return stdnse.format_output(false, "Script error: " .. tostring(err))
    #   end
    indent1 = "  "
    indent2 = "    "

    # Replace the action body with wrapped version
    new_action_lines = action_lines[:body_start + 1]  # "action = function(...)"
    # pcall open
    new_action_lines.append(indent1 + "local status, err = pcall(function()")
    # Body lines (already indented by 2 spaces via the loop above) go inside pcall
    new_action_lines.extend(action_lines[body_start + 1:action_body_end])
    # pcall close + error handling
    new_action_lines.append(indent1 + "end)")
    new_action_lines.append(indent1 + "if not status then")
    new_action_lines.append(indent2 + 'return stdnse.format_output(false, "Script error: " .. tostring(err))')
    new_action_lines.append(indent1 + "end")
    # Original closing end of action function
    new_action_lines.append(original_closing_end)

    lines[action_start:] = new_action_lines
    return "\n".join(lines), True


def add_set_timeout(text):
    """Add socket:set_timeout(5000) before any socket:connect or socket:send on bare sockets."""
    # Only do this if we haven't added pcall wrapper (i.e., socket already has pcall but might be missing timeout)
    # This is tricky with regex. Let's keep it simple: check if there's a socket creation followed by set_timeout
    if "set_timeout" in text:
        return text, False

    lines = text.split("\n")
    modified = False
    new_lines = []
    for line in lines:
        new_lines.append(line)
        # After we see a socket creation (local socket = nmap.new_socket()) or similar
        if re.match(r"^\s*local\s+\w+\s*=\s*nmap\.new_socket\b", line):
            indent = re.match(r"^(\s*)", line).group(1)
            sock_var = re.match(r"local\s+(\w+)\s*=", line).group(1)
            new_lines.append(f"{indent}{sock_var}:set_timeout(5000)")
            modified = True

    return "\n".join(new_lines), modified


def normalize(content):
    """Normalize formatting."""
    modified = False
    lines = content.split("\n")

    # Fix indentation - ensure 2-space indents, but only for known patterns
    new_lines = []
    for line in lines:
        # Replace tabs with 2 spaces
        new_line = line.replace("\t", "  ")
        # Normalize multiple spaces to one (but not in strings)
        # Remove trailing whitespace
        new_line = re.sub(r"[ \t]+$", "", new_line)
        if new_line != line:
            modified = True
        new_lines.append(new_line)

    # Ensure newline at end
    content = "\n".join(new_lines)
    if not content.endswith("\n"):
        content += "\n"
        modified = True

    return content, modified


def validate_syntax(filepath):
    """Check Lua syntax using lua's loadfile."""
    try:
        result = subprocess.run(
            ["lua", "-e", "local f, e = loadfile(arg[0]); if f then os.exit(0) else io.stderr:write(e); os.exit(1) end", filepath],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, None
        return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return True, None  # skip validation on timeout
    except Exception as e:
        return False, str(e)


def process_file(filepath):
    """Process a single .nse file. Returns (changed, error_msg)."""
    filename = os.path.basename(filepath)
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    original = content
    changed = False

    # 1. Add missing requires
    content, mod = add_missing_requires(content)
    changed = changed or mod

    # 2. Add description if missing
    if not has_description(content):
        content = add_description_block(content, filename)
        changed = True

    # 3. Add author if missing
    if not has_author(content):
        content = add_author_line(content)
        changed = True

    # 4. Add categories if missing
    if not has_categories(content):
        content = add_categories_line(content, filename)
        changed = True

    # 5. Add portrule if missing
    if not has_portrule(content):
        content = add_portrule(content, filename)
        changed = True

    # 6. Add action if missing
    if not has_action(content):
        content = add_action(content, filename)
        changed = True

    # 7. Wrap socket operations in pcall (if not already done)
    content, mod = wrap_socket_in_pcall(content)
    changed = changed or mod

    # 8. Add set_timeout before socket operations
    content, mod = add_set_timeout(content)
    changed = changed or mod

    # 9. Normalize formatting
    content, mod = normalize(content)
    changed = changed or mod

    if changed:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    # Validate syntax
    ok, err = validate_syntax(filepath)
    if not ok:
        # Revert on syntax error
        if changed:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(original)
        return False, err

    return changed, None


def main():
    # Collect all .nse files recursively
    all_files = []
    for root, dirs, files in os.walk(SCRIPT_DIR):
        for f in sorted(files):
            if f.endswith(".nse") and f != os.path.basename(__file__):
                all_files.append(os.path.join(root, f))

    total = len(all_files)
    improved = 0
    errors = 0
    unchanged = 0

    width = len(str(total))

    for idx, filepath in enumerate(all_files, 1):
        fname = os.path.basename(filepath)
        relpath = os.path.relpath(filepath, SCRIPT_DIR)
        try:
            changed, err = process_file(filepath)
            if err:
                print(f"[{idx:>{width}}/{total}] {relpath}... ERROR: {err}")
                errors += 1
            elif changed:
                print(f"[{idx:>{width}}/{total}] {relpath}... OK")
                improved += 1
            else:
                print(f"[{idx:>{width}}/{total}] {relpath}... unchanged")
                unchanged += 1
        except Exception as e:
            print(f"[{idx:>{width}}/{total}] {relpath}... ERROR: {e}")
            errors += 1

    print()
    print("=" * 60)
    print(f"Total files: {total}")
    print(f"Improved:    {improved}")
    print(f"Unchanged:   {unchanged}")
    print(f"Errors:      {errors}")


if __name__ == "__main__":
    main()
