# Data Directory

This directory stores exported SQL dumps for syncing between Linux server and Mac local.

## Files

- `device_records_*.sql` — All scanned IoT devices (Shodan/Censys)
- `pipeline_runs_*.sql` — Pipeline execution history
- `shodan_query_runs_*.sql` — Shodan query audit trail

These are **ignored by Git** (see `.gitignore`) but can be manually copied.

## Workflow

### Export (on Linux server)
```bash
make export-data
```

### Sync (via Git LFS or manual transfer)
```bash
# Option 1: Manual push (if Git LFS is available)
git add data/*.sql
git commit -m "Export device data"
git push

# Option 2: Manual SCP
scp data/*.sql your-mac:~/Downloads/
```

### Import (on Mac)
```bash
git pull  # if using Git method
make import-data
```

## Notes

- SQL dumps are **not committed to Git** by default (too large, frequent changes)
- If you want version control: enable **Git LFS** (`brew install git-lfs`)
- Or use **manual transfer** via SCP/Dropbox
