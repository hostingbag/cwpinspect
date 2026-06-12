#!/usr/bin/env bash
#
# CWP incident remediation helper
#
# This script removes only the known compromise indicators observed across the
# inspected CWP servers. It is intentionally conservative:
#   - dry-run by default
#   - requires --apply to change anything
#   - backs up every touched file under /root/incident-cleanup-YYYYmmddHHMMSS/
#   - upload PHP/PHTML removal is extra opt-in with --remove-upload-php
#   - CSF blocking is extra opt-in with --block-ips
#
# Recommended:
#   bash cwp_incident_readonly_scan.sh
#   bash cwp_incident_remediate.sh --dry-run
#   bash cwp_incident_remediate.sh --apply
#   bash cwp_incident_remediate.sh --apply --remove-upload-php --block-ips
#   bash cwp_incident_readonly_scan.sh
#
# This script does not harden SSH or restrict CWP ports because that can lock out
# administrators unless an alternate sudo user and allow-listed IPs are tested.

set -u
set -o pipefail

APPLY=0
REMOVE_UPLOAD_PHP=0
BLOCK_IPS=0
ASSUME_YES=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) APPLY=0 ;;
    --apply) APPLY=1 ;;
    --remove-upload-php) REMOVE_UPLOAD_PHP=1 ;;
    --block-ips) BLOCK_IPS=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --help|-h)
      sed -n '1,40p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

TS="$(date +%Y%m%d%H%M%S)"
BK="/root/incident-cleanup-$TS"
mkdir -p "$BK"/{backups,logs}

BAD_SSH_KEY="AAAAC3NzaC1lZDI1NTE5AAAAIPCsi58xDKuXuq8CMnlIFQHoqiGkyziMQpAks2t0EBa0"
BAD_HASH="d94f75a70b5cabaf786ac57177ed841732e62bdcc9a29e06e5b41d9be567bcfa"
BAD_IPS="89.248.172.183 94.102.55.16"
MAL_SUDOERS="bin daemon lp mail games nobody systemd-resolve systemd-network polkitd tss sshd postfix dovecot dovenull mysql vmail opendkim redis"

log() {
  printf '%s\n' "$*" | tee -a "$BK/logs/remediation.log"
}

doit() {
  if [ "$APPLY" -eq 1 ]; then
    log "RUN: $*"
    "$@"
  else
    log "DRY-RUN: $*"
  fi
}

backup_file() {
  f="$1"
  [ -e "$f" ] || return 0
  if [ ! -f "$f" ]; then
    log "SKIP_BACKUP_NOT_REGULAR_FILE: $f"
    return 0
  fi
  rel="${f#/}"
  dest="$BK/backups/$rel"
  mkdir -p "$(dirname "$dest")"
  if [ ! -e "$dest" ]; then
    cp -p "$f" "$dest"
    printf '%s\t%s\n' "$f" "$dest" >> "$BK/logs/backup-map.tsv"
    log "BACKUP: $f -> $dest"
  fi
}

confirm_apply() {
  if [ "$APPLY" -eq 0 ]; then
    return 0
  fi
  if [ "$ASSUME_YES" -eq 1 ]; then
    return 0
  fi
  echo
  echo "This will modify the server. Backups will be written to: $BK"
  echo "Type APPLY to continue:"
  read -r answer
  [ "$answer" = "APPLY" ] || {
    echo "Aborted."
    exit 1
  }
}

remove_file() {
  f="$1"
  [ -e "$f" ] || return 0
  backup_file "$f"
  doit rm -f "$f"
}

section() {
  log ""
  log "== $1 =="
}

confirm_apply

section "Mode"
log "backup_dir=$BK"
log "apply=$APPLY"
log "remove_upload_php=$REMOVE_UPLOAD_PHP"
log "block_ips=$BLOCK_IPS"

section "Remove Known CWP Webshell Artifacts"
for f in \
  /usr/local/cwpsrv/var/services/roundcube/temp/.x.php \
  /usr/local/cwpsrv/var/services/oauth/v1.0a/server/www/.r.php \
  /usr/local/apache/htdocs/webftp_simple/images/.s.php \
  /usr/local/apache/htdocs/webftp_simple/skins/.s.php \
  /tmp/.cwp_script.sh; do
  if [ -e "$f" ]; then
    log "FOUND: $f"
    remove_file "$f"
  fi
done

section "Remove Malicious SSH Key Lines"
find /root /home -path '*/.ssh/authorized_keys' -type f -print 2>/dev/null > "$BK/logs/authorized_key_files.txt"
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if grep -q "$BAD_SSH_KEY" "$f" 2>/dev/null; then
    log "FOUND_BAD_KEY: $f"
    backup_file "$f"
    if [ "$APPLY" -eq 1 ]; then
      tmp="$f.clean.$$"
      grep -v "$BAD_SSH_KEY" "$f" > "$tmp"
      chown --reference="$f" "$tmp"
      chmod --reference="$f" "$tmp"
      /bin/mv -f "$tmp" "$f"
    else
      log "DRY-RUN: remove lines containing $BAD_SSH_KEY from $f"
    fi
  fi
done < "$BK/logs/authorized_key_files.txt"

section "Remove Malicious Sudoers Drop-ins"
for name in $MAL_SUDOERS; do
  f="/etc/sudoers.d/$name"
  [ -f "$f" ] || continue
  if grep -Eq 'NOPASSWD:[[:space:]]*ALL|ALL[[:space:]]*=[[:space:]]*\(ALL\)[[:space:]]*NOPASSWD' "$f" && [ "$(wc -c < "$f")" -lt 500 ]; then
    log "FOUND_SUDOERS_BACKDOOR: $f"
    remove_file "$f"
  else
    log "SKIP_SUDOERS_NOT_MATCHED: $f"
  fi
done
if [ "$APPLY" -eq 1 ] && command -v visudo >/dev/null 2>&1; then
  visudo -c | tee -a "$BK/logs/visudo-check.txt"
fi

section "Remove Cron Persistence"
find /etc/cron* /var/spool/cron -type f -print 2>/dev/null > "$BK/logs/cron_files.txt"
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if grep -Eq 'defunct-kernel|suspicious-cpg|\.config/htop/defunct|/usr/bin/defunct|base64 -d\|bash' "$f" 2>/dev/null; then
    log "FOUND_SUSPICIOUS_CRON: $f"
    backup_file "$f"
    if [ "$APPLY" -eq 1 ]; then
      tmp="$f.clean.$$"
      grep -Ev 'defunct-kernel|suspicious-cpg|\.config/htop/defunct|/usr/bin/defunct|base64 -d\|bash' "$f" > "$tmp"
      chown --reference="$f" "$tmp"
      chmod --reference="$f" "$tmp"
      if [ -s "$tmp" ]; then
        /bin/mv -f "$tmp" "$f"
      else
        rm -f "$tmp"
        rm -f "$f"
      fi
    else
      log "DRY-RUN: remove suspicious cron lines or empty cron file $f"
    fi
  fi
done < "$BK/logs/cron_files.txt"

section "Stop Known Malware Processes"
ps -eo pid=,args= | grep -E '/home/.*/\.config/htop/defunct|/usr/bin/defunct|exec -a .*\[kswapd0\].*defunct|exec -a .*\[card0-crtc8\].*defunct' | grep -v grep > "$BK/logs/malware_processes.txt" || true
while read -r pid args; do
  [ -n "${pid:-}" ] || continue
  log "FOUND_PROCESS: pid=$pid args=$args"
  doit kill "$pid"
done < "$BK/logs/malware_processes.txt"

section "Remove Known Malware Files"
for f in /usr/bin/defunct /home/*/.config/htop/defunct; do
  [ -f "$f" ] || continue
  hash="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
  if [ "$hash" = "$BAD_HASH" ]; then
    log "FOUND_BAD_HASH: $f"
    remove_file "$f"
    dat="$(dirname "$f")/defunct.dat"
    [ -e "$dat" ] && remove_file "$dat"
  else
    log "SKIP_HASH_MISMATCH: $f hash=$hash"
  fi
done

section "Clean Exact PHP Injection Lines"
find /home -type f \( -name '*.php' -o -name '*.phtml' \) -print 2>/dev/null > "$BK/logs/php_files.txt"
xargs -r grep -Il 'eval(base64_decode("aW5pX3NldC' < "$BK/logs/php_files.txt" 2>/dev/null > "$BK/logs/exact_injected_php_files.txt" || true
while IFS= read -r f; do
  [ -f "$f" ] || continue
  log "FOUND_EXACT_WEB_INJECTION: $f"
  backup_file "$f"
  if [ "$APPLY" -eq 1 ]; then
    tmp="$f.clean.$$"
    awk '!/^[[:space:]]*eval\(base64_decode\("aW5pX3NldC/' "$f" > "$tmp"
    chown --reference="$f" "$tmp"
    chmod --reference="$f" "$tmp"
    /bin/mv -f "$tmp" "$f"
  else
    log "DRY-RUN: remove standalone exact eval(base64_decode) injection lines from $f"
  fi
done < "$BK/logs/exact_injected_php_files.txt"

section "Remove Non-index PHP/PHTML In Uploads"
if [ "$REMOVE_UPLOAD_PHP" -eq 1 ]; then
  find /home -path '*/uploads/*' -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) ! -name 'index.php' -print 2>/dev/null \
    > "$BK/logs/upload_php_nonindex.txt"
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    log "FOUND_UPLOAD_EXECUTABLE: $f"
    remove_file "$f"
  done < "$BK/logs/upload_php_nonindex.txt"
else
  log "SKIPPED: use --remove-upload-php to remove non-index PHP/PHTML inside uploads"
  find /home -path '*/uploads/*' -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) ! -name 'index.php' -print 2>/dev/null \
    > "$BK/logs/upload_php_nonindex.review_only.txt"
fi

section "Block Known Attacker IPs In CSF"
if [ "$BLOCK_IPS" -eq 1 ]; then
  if command -v csf >/dev/null 2>&1; then
    for ip in $BAD_IPS; do
      log "CSF_DENY: $ip"
      doit csf -d "$ip" "CWP exploit source"
    done
  else
    log "SKIPPED: csf command not found"
  fi
else
  log "SKIPPED: use --block-ips to add known attacker IPs to csf.deny"
fi

section "Validation"
find /root /home -path '*/.ssh/authorized_keys' -type f -exec grep -Hn "$BAD_SSH_KEY" {} \; \
  > "$BK/logs/remaining_bad_ssh_key.txt" 2>/dev/null || true
find /usr/bin /home/*/.config/htop -type f -name 'defunct' -exec sha256sum {} \; 2>/dev/null | grep "$BAD_HASH" > "$BK/logs/remaining_bad_hash.txt" || true
find /home -path '*/uploads/*' -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) ! -name 'index.php' -print 2>/dev/null > "$BK/logs/remaining_upload_php_nonindex.txt"
xargs -r grep -Il 'eval(base64_decode("aW5pX3NldC' < "$BK/logs/php_files.txt" 2>/dev/null > "$BK/logs/remaining_exact_web_injection.txt" || true

log "remaining_bad_ssh_key=$(wc -l < "$BK/logs/remaining_bad_ssh_key.txt")"
log "remaining_bad_hash=$(wc -l < "$BK/logs/remaining_bad_hash.txt")"
log "remaining_upload_php_nonindex=$(wc -l < "$BK/logs/remaining_upload_php_nonindex.txt")"
log "remaining_exact_web_injection=$(wc -l < "$BK/logs/remaining_exact_web_injection.txt")"

section "Next Manual Steps"
log "1. Re-run cwp_incident_readonly_scan.sh and compare counts."
log "2. Verify websites locally and externally."
log "3. Create/test alternate sudo user before SSH hardening."
log "4. Restrict SSH/CWP/admin ports in CSF only after allowed IPs are tested."
log "5. Disable direct root SSH only after alternate sudo login is confirmed."
log "Done. Backup and logs: $BK"
