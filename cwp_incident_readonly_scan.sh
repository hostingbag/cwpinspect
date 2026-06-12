#!/usr/bin/env bash
#
# CWP incident read-only scanner
# Purpose: collect evidence and indicators for the CWP compromise pattern seen on
# multiple servers. This script does not delete, edit, restart, block, or kill.
#
# Run:
#   bash cwp_incident_readonly_scan.sh
#   bash cwp_incident_readonly_scan.sh --deep
#
# Output:
#   /root/incident-readonly-YYYYmmddHHMMSS/
#

set -u
set -o pipefail

DEEP=0
if [ "${1:-}" = "--deep" ]; then
  DEEP=1
fi

TS="$(date +%Y%m%d%H%M%S)"
OUT="/root/incident-readonly-$TS"
mkdir -p "$OUT"/{system,auth,cwp,persistence,web,network,firewall,logs}

BAD_SSH_KEY="AAAAC3NzaC1lZDI1NTE5AAAAIPCsi58xDKuXuq8CMnlIFQHoqiGkyziMQpAks2t0EBa0"
BAD_HASH="d94f75a70b5cabaf786ac57177ed841732e62bdcc9a29e06e5b41d9be567bcfa"
BAD_IP_RE='89\.248\.172\.183|94\.102\.55\.16'
BAD_WEB_RE='eval\(base64_decode\("aW5pX3NldC|akam60800|eval\(gzuncompress\(base64_decode|eval\(gzinflate\(|base64_decode\(\$_(POST|REQUEST|COOKIE)|assert\(\$_(POST|REQUEST|COOKIE)|FilesMan|c99|r57|shell_exec\(|passthru\(|system\(\$_(POST|REQUEST|COOKIE)'
FALSE_POSITIVE_RE='WSODs|data:image/png;base64|xlink:href="data:image'

section() {
  printf '\n== %s ==\n' "$1" | tee -a "$OUT/summary.txt"
}

count_file() {
  label="$1"
  file="$2"
  if [ -f "$file" ]; then
    printf '%s: %s\n' "$label" "$(wc -l < "$file")" | tee -a "$OUT/summary.txt"
  else
    printf '%s: 0\n' "$label" | tee -a "$OUT/summary.txt"
  fi
}

run_capture() {
  name="$1"
  shift
  "$@" > "$OUT/$name" 2>&1 || true
}

section "Report"
{
  echo "output_dir=$OUT"
  echo "timestamp=$TS"
  echo "hostname=$(hostname -f 2>/dev/null || hostname)"
  echo "kernel=$(uname -a)"
  echo "mode=$([ "$DEEP" -eq 1 ] && echo deep || echo normal)"
} | tee -a "$OUT/summary.txt"

section "System Inventory"
run_capture system/os-release sh -c 'cat /etc/*release 2>/dev/null'
run_capture system/hostnamectl hostnamectl
run_capture system/uptime uptime
run_capture system/users-passwd sh -c 'cat /etc/passwd'
run_capture system/shadow-age chage -l root
run_capture system/sudoers-ls sh -c 'ls -la /etc/sudoers.d 2>/dev/null'
run_capture system/sudoers-content sh -c 'for f in /etc/sudoers /etc/sudoers.d/*; do [ -f "$f" ] && echo "### $f" && sed -n "1,120p" "$f"; done'

section "SSH Configuration"
run_capture auth/sshd-T sh -c 'sshd -T 2>/dev/null | egrep "^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile|allowusers|denyusers|passwordauthentication) "'
run_capture auth/sshd-config sh -c 'sed -n "1,240p" /etc/ssh/sshd_config 2>/dev/null'
run_capture auth/current-sessions who
run_capture auth/last-logins last -ai
run_capture auth/lastb-failed sh -c 'lastb -ai 2>/dev/null | head -300'

section "SSH Authorized Keys"
find /root /home -path '*/.ssh/authorized_keys' -type f -print 2>/dev/null > "$OUT/auth/authorized_key_files.txt"
while IFS= read -r f; do
  stat -c '%U:%G %a %n' "$f" 2>/dev/null
done < "$OUT/auth/authorized_key_files.txt" > "$OUT/auth/authorized_key_stats.txt"
while IFS= read -r f; do
  grep -Hn "$BAD_SSH_KEY" "$f" 2>/dev/null
done < "$OUT/auth/authorized_key_files.txt" > "$OUT/auth/bad_ssh_key_hits.txt"
count_file "known_bad_ssh_key_hits" "$OUT/auth/bad_ssh_key_hits.txt"

section "CWP Exploit Indicators"
run_capture cwp/version sh -c 'cat /usr/local/cwpsrv/htdocs/resources/admin/include/version.php /usr/local/cwpsrv/version 2>/dev/null'
find /usr/local/cwpsrv/var/services/roundcube/temp \
     /usr/local/cwpsrv/var/services/oauth/v1.0a/server/www \
     /usr/local/apache/htdocs/webftp_simple/images \
     /usr/local/apache/htdocs/webftp_simple/skins \
     -maxdepth 1 -type f \( -name '.*.php' -o -name '*.php' \) -print 2>/dev/null > "$OUT/cwp/suspicious_cwp_php_files.txt"
for f in \
  /usr/local/cwpsrv/var/services/roundcube/temp/.x.php \
  /usr/local/cwpsrv/var/services/oauth/v1.0a/server/www/.r.php \
  /usr/local/apache/htdocs/webftp_simple/images/.s.php \
  /usr/local/apache/htdocs/webftp_simple/skins/.s.php \
  /tmp/.cwp_script.sh; do
  [ -e "$f" ] && ls -la "$f"
done > "$OUT/cwp/known_cwp_artifacts.txt" 2>/dev/null || true
grep -RInE 'login=\$\(|mars\.imasync|410\.txt|\.cwp_script|/temp/\.x\.php|/\.r\.php|/\.s\.php|89\.248\.172\.183|94\.102\.55\.16' \
  /usr/local/cwpsrv/logs /usr/local/apache/logs /var/log/httpd /var/log 2>/dev/null \
  | head -5000 > "$OUT/cwp/cwp_exploit_log_hits.txt" || true
count_file "cwp_exploit_log_hits" "$OUT/cwp/cwp_exploit_log_hits.txt"
count_file "known_cwp_artifacts" "$OUT/cwp/known_cwp_artifacts.txt"

section "Persistence"
find /etc/cron* /var/spool/cron -type f -print 2>/dev/null > "$OUT/persistence/cron_files.txt"
grep -RInE 'defunct-kernel|suspicious-cpg|base64 -d\|bash|\.config/htop|/usr/bin/defunct|mars\.imasync|curl .*\.php|wget .*\.php' \
  /etc/cron* /var/spool/cron 2>/dev/null > "$OUT/persistence/suspicious_cron_hits.txt" || true
find /etc/systemd /usr/lib/systemd /lib/systemd -type f -name '*.service' -o -name '*.timer' 2>/dev/null \
  | xargs -r grep -HnE 'defunct|\.config/htop|card0-crtc8|kswapd0|mars\.imasync|/tmp/\.|curl|wget' \
  > "$OUT/persistence/suspicious_systemd_hits.txt" 2>/dev/null || true
grep -RInE 'defunct|\.config/htop|curl|wget|base64 -d|/tmp/\.|mars\.imasync' \
  /etc/profile /etc/bashrc /etc/profile.d /root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.bash_profile \
  > "$OUT/persistence/suspicious_profile_hits.txt" 2>/dev/null || true
count_file "suspicious_cron_hits" "$OUT/persistence/suspicious_cron_hits.txt"
count_file "suspicious_systemd_hits" "$OUT/persistence/suspicious_systemd_hits.txt"
count_file "suspicious_profile_hits" "$OUT/persistence/suspicious_profile_hits.txt"

section "Known Malware Files And Processes"
for f in /usr/bin/defunct /tmp/.cwp_script.sh /home/*/.config/htop/defunct /home/*/.config/htop/defunct.dat; do
  [ -e "$f" ] && ls -la "$f" && sha256sum "$f" 2>/dev/null
done > "$OUT/persistence/known_malware_files.txt" 2>/dev/null || true
grep "$BAD_HASH" "$OUT/persistence/known_malware_files.txt" > "$OUT/persistence/known_bad_hash_hits.txt" 2>/dev/null || true
ps -eo pid,user,ppid,lstart,comm,args \
  | egrep 'defunct|\.config/htop|\[kswapd0\]|\[card0-crtc8\]|\[watchdogd\]' \
  | grep -v egrep > "$OUT/persistence/suspicious_processes.txt" || true
count_file "known_bad_hash_hits" "$OUT/persistence/known_bad_hash_hits.txt"
count_file "suspicious_process_lines" "$OUT/persistence/suspicious_processes.txt"

section "Network And Firewall"
run_capture network/listening ss -tulpen
run_capture network/connections ss -tunap
egrep "$BAD_IP_RE" "$OUT/network/connections" > "$OUT/network/bad_ip_connections.txt" 2>/dev/null || true
if command -v csf >/dev/null 2>&1; then
  run_capture firewall/csf-status csf -l
  run_capture firewall/csf-conf sh -c 'grep -E "^(TESTING|TCP_IN|TCP6_IN|TCP_OUT|RESTRICT_SYSLOG|LF_|CT_|PORTFLOOD)" /etc/csf/csf.conf'
  run_capture firewall/csf-allow sh -c 'cat /etc/csf/csf.allow 2>/dev/null'
  run_capture firewall/csf-deny sh -c 'cat /etc/csf/csf.deny 2>/dev/null'
fi
count_file "bad_ip_connections" "$OUT/network/bad_ip_connections.txt"

section "Apache Vhosts And Health"
find /usr/local/apache/conf.d/vhosts /usr/local/apache/conf.d -type f \( -name '*.conf' -o -name 'vhosts*.conf' \) -print 2>/dev/null \
  > "$OUT/web/vhost_conf_files.txt"
awk '
  BEGIN{server=""; doc=""}
  /^[[:space:]]*ServerName[[:space:]]+/ {server=$2}
  /^[[:space:]]*DocumentRoot[[:space:]]+/ {doc=$2; gsub(/"/,"",doc)}
  server != "" && doc != "" {print server " " doc; server=""; doc=""}
' $(cat "$OUT/web/vhost_conf_files.txt") 2>/dev/null | sort -u > "$OUT/web/domains_docs.txt"
awk '{print $2}' "$OUT/web/domains_docs.txt" | sort -u | grep '^/home/' > "$OUT/web/home_docroots.txt" || true

while read -r domain doc; do
  [ -n "$domain" ] || continue
  code="$(curl -sS -o /dev/null -m 12 -w '%{http_code}' -H "Host: $domain" http://127.0.0.1/ 2>/dev/null || echo 000)"
  size="$(curl -sS -m 12 -H "Host: $domain" http://127.0.0.1/ 2>/dev/null | wc -c)"
  exists=no
  [ -d "$doc" ] && exists=yes
  printf '%s\t%s\t%s\t%s %s\n' "$code" "$size" "$exists" "$domain" "$doc"
done < "$OUT/web/domains_docs.txt" > "$OUT/web/http_health.tsv"
awk -F'\t' '$1 !~ /^2|^3/ || $3 != "yes" {print}' "$OUT/web/http_health.tsv" > "$OUT/web/http_non200_or_missing.tsv"
count_file "vhost_count" "$OUT/web/domains_docs.txt"
count_file "http_non200_or_missing" "$OUT/web/http_non200_or_missing.tsv"

section "Website Malware Indicators"
: > "$OUT/web/bounded_scan_files.txt"
while IFS= read -r d; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 3 -type f \( -name 'index.php' -o -name 'wp-config.php' -o -name '*.phtml' \) 2>/dev/null >> "$OUT/web/bounded_scan_files.txt"
  find "$d/wp-content/mu-plugins" "$d/wp-content/plugins" "$d/wp-content/themes" "$d/wp-includes" "$d/wp-admin" \
    -maxdepth 4 -type f -name '*.php' 2>/dev/null >> "$OUT/web/bounded_scan_files.txt"
  find "$d" -path '*/uploads/*' -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) 2>/dev/null >> "$OUT/web/bounded_scan_files.txt"
done < "$OUT/web/home_docroots.txt"
sort -u "$OUT/web/bounded_scan_files.txt" -o "$OUT/web/bounded_scan_files.txt"

xargs -r grep -nE "$BAD_WEB_RE" < "$OUT/web/bounded_scan_files.txt" 2>/dev/null \
  | grep -Ev "$FALSE_POSITIVE_RE" > "$OUT/web/malware_hits_filtered.txt" || true
awk -F: '{print $1}' "$OUT/web/malware_hits_filtered.txt" | sort -u > "$OUT/web/malware_hit_files.txt"

: > "$OUT/web/uploads_php_files.txt"
while IFS= read -r d; do
  [ -d "$d" ] && find "$d" -path '*/uploads/*' -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) 2>/dev/null >> "$OUT/web/uploads_php_files.txt"
done < "$OUT/web/home_docroots.txt"
awk '!/\/index\.php$/ {print}' "$OUT/web/uploads_php_files.txt" > "$OUT/web/uploads_php_nonindex.txt"
grep -Ei '/(anonfox|ws0|uploader|orc|f5|xy|shell|wso|c99|r57)\.(php|phtml)$' \
  "$OUT/web/uploads_php_nonindex.txt" > "$OUT/web/obvious_upload_webshell_names.txt" 2>/dev/null || true

count_file "bounded_web_files_scanned" "$OUT/web/bounded_scan_files.txt"
count_file "malware_pattern_hit_files" "$OUT/web/malware_hit_files.txt"
count_file "nonindex_upload_php" "$OUT/web/uploads_php_nonindex.txt"
count_file "obvious_upload_webshell_names" "$OUT/web/obvious_upload_webshell_names.txt"

if [ "$DEEP" -eq 1 ]; then
  section "Deep Website Scan"
  while IFS= read -r d; do
    [ -d "$d" ] || continue
    grep -RIn --include='*.php' --include='*.phtml' --include='*.inc' -E "$BAD_WEB_RE" "$d" 2>/dev/null
  done < "$OUT/web/home_docroots.txt" | grep -Ev "$FALSE_POSITIVE_RE" > "$OUT/web/deep_malware_hits_filtered.txt" || true
  awk -F: '{print $1}' "$OUT/web/deep_malware_hits_filtered.txt" | sort -u > "$OUT/web/deep_malware_hit_files.txt"
  count_file "deep_malware_hit_files" "$OUT/web/deep_malware_hit_files.txt"
fi

section "Recent Web PHP Files"
: > "$OUT/web/recent_php_files_7d.txt"
while IFS= read -r d; do
  [ -d "$d" ] && find "$d" -type f \( -name '*.php' -o -name '*.phtml' \) -mtime -7 \
    -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %p\n' 2>/dev/null >> "$OUT/web/recent_php_files_7d.txt"
done < "$OUT/web/home_docroots.txt"
sort "$OUT/web/recent_php_files_7d.txt" -o "$OUT/web/recent_php_files_7d.txt"
count_file "recent_php_files_7d" "$OUT/web/recent_php_files_7d.txt"

section "Recommended Manual Review"
{
  echo "Review these files first:"
  echo "- $OUT/summary.txt"
  echo "- $OUT/cwp/cwp_exploit_log_hits.txt"
  echo "- $OUT/auth/bad_ssh_key_hits.txt"
  echo "- $OUT/persistence/suspicious_cron_hits.txt"
  echo "- $OUT/persistence/suspicious_systemd_hits.txt"
  echo "- $OUT/persistence/known_malware_files.txt"
  echo "- $OUT/web/malware_hits_filtered.txt"
  echo "- $OUT/web/uploads_php_nonindex.txt"
  echo "- $OUT/web/obvious_upload_webshell_names.txt"
  echo "- $OUT/web/http_non200_or_missing.tsv"
  echo
  echo "High priority remediation indicators:"
  echo "- Any known_bad_ssh_key_hits > 0"
  echo "- Any known_bad_hash_hits > 0"
  echo "- Any suspicious sudoers drop-ins for system users"
  echo "- Any cron containing defunct-kernel or base64 decoded bash"
  echo "- Any non-index PHP/PHTML under uploads"
  echo "- Any eval/base64/gzinflate hits outside known legitimate libraries"
  echo "- CWP/admin/SSH ports globally exposed in CSF TCP_IN"
  echo "- PermitRootLogin yes or PasswordAuthentication yes on internet-exposed SSH"
} | tee -a "$OUT/summary.txt"

printf '\nDone. Evidence directory: %s\n' "$OUT" | tee -a "$OUT/summary.txt"
