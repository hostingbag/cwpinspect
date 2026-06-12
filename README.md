# cwpinspect

Separate scripts for inspecting and cleaning the known CWP compromise pattern.

## 1. Read-only inspection

Use this first. It does not delete, edit, restart, block, or kill anything.

```bash
bash cwp_incident_readonly_scan.sh
bash cwp_incident_readonly_scan.sh --deep
```

Inspection reports are written to:

```text
/root/incident-readonly-YYYYmmddHHMMSS/
```

## 2. Separate cleanup/removal script

Run this only after reviewing the read-only report.

Dry run:

```bash
bash cwp_incident_remediate.sh --dry-run
```

Apply conservative cleanup:

```bash
bash cwp_incident_remediate.sh --apply
```

Also remove non-index PHP/PHTML files inside upload directories:

```bash
bash cwp_incident_remediate.sh --apply --remove-upload-php
```

Also block known attacker IPs in CSF:

```bash
bash cwp_incident_remediate.sh --apply --block-ips
```

Full known cleanup:

```bash
bash cwp_incident_remediate.sh --apply --remove-upload-php --block-ips
```

Cleanup backups and logs are written to:

```text
/root/incident-cleanup-YYYYmmddHHMMSS/
```

The cleanup script backs up only the individual regular files it is going to edit or remove. It does not back up the full `/home` directory or full website directories.

Backup paths preserve the original path under `backups/`. Example:

```text
Original: /home/user/public_html/wp-content/uploads/a/shell.php
Backup:   /root/incident-cleanup-YYYYmmddHHMMSS/backups/home/user/public_html/wp-content/uploads/a/shell.php
```

A restore map is also written here:

```text
/root/incident-cleanup-YYYYmmddHHMMSS/logs/backup-map.tsv
```

The cleanup script removes only known indicators such as malicious SSH keys, malicious sudoers drop-ins, defunct cron/process/files, known CWP webshell artifacts, exact PHP injection lines, and optionally upload PHP/PHTML files.

It does not automatically harden SSH or restrict CWP ports because that can lock out administrators unless an alternate sudo user and allow-listed IPs are tested first.
