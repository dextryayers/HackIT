# reports - generated output storage

Storage directory for non-interactive scan outputs written by reporters and
engines. Not a tool and not a CLI module.

## Contents

- `analys/` - deep-scan (`hackit analys`) JSON reports, one file per run
- `swarm/` - swarm/autopilot agent run outputs

Files are timestamped and keyed by target/sample so concurrent runs do not
collide. They carry no standalone functionality: read them with `jq`, import
them into your CI, or delete them when you no longer need them.

If disk fills up, prune with:

```bash
rm -f hackit/reports/analys/*.json hackit/reports/swarm/*.json
```

Treat anything in here as potentially sensitive: scan reports often contain
hostnames, IPs, fingerprints and finding details from engagements. This repo
only partially gitignores generated artifacts; review `.gitignore` and exclude
anything you do not want tracked.
