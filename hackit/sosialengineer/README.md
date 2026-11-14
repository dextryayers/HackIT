# sosialengineer - legacy social-engineering launcher

This directory does not implement a standalone tool. It ships one shell
wrapper, `run_sosialengineer.sh`, which redirects into the global HackIT
Swarm/launcher (`../../hackit.sh`) for the `sosialengineer` mode.

If you are looking for social-engineering workflows in this tree, the real
implementation lives in `hackit/agent/` (swarm, autopilot, TUI dashboard) and
`hackit/sosialengineer/` exists only as a thin compatibility shim for muscle
memory.

## What the wrapper does

```bash
./run_sosialengineer.sh [args...]
```

- Prints the target module name.
- Verifies the global wrapper exists at `../../hackit.sh`.
- Delegates: `../../hackit.sh -mode sosialengineer "$@"`
- Fails loudly with a non-zero exit if the global wrapper is missing.

No scanning, harvesting, pretexting or interaction logic is implemented
here. Use the swarm/autopilot entry points instead. For authorized phishing
and awareness testing, run those flows against your own organization with
documented consent.
