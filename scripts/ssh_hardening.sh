#!/usr/bin/env bash
#
# ssh_hardening.sh — RoboShield
# Harden the OpenSSH server safely and idempotently.
#
#   - Disables root SSH login (handles the "PermitRootLogin yes" case, which the
#     old version silently skipped).
#   - Applies a small set of conservative directives that carry no lockout risk.
#   - Disables PasswordAuthentication ONLY when key-based access already exists,
#     so it can never lock you out of a key-less host.
#   - Prefers a drop-in under /etc/ssh/sshd_config.d (Ubuntu's Include model);
#     falls back to editing the main file with a marked, idempotent block.
#   - Validates with `sshd -t` BEFORE reloading and confirms the EFFECTIVE
#     config with `sshd -T` AFTER. Reloads (not restarts) to keep your session.
#
# Re-runnable. Run as root for a real change. Flags:
#   --dry-run             show intended changes, touch nothing
#   --no-restart          write config but do not validate/reload the service
#   --force-password-off  disable PasswordAuthentication even without a detected key
#   -h | --help
#
# Test hooks (override to drive against a throwaway config; see the harness):
#   SSHD_CONFIG, SSHD_CONFD_DIR, SSHD_BIN
#
set -euo pipefail

SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
SSHD_CONFD_DIR="${SSHD_CONFD_DIR:-/etc/ssh/sshd_config.d}"
SSHD_BIN="${SSHD_BIN:-}"
DROPIN_NAME="00-roboshield-hardening.conf"
MARKER_BEGIN="# >>> RoboShield hardening >>>"
MARKER_END="# <<< RoboShield hardening <<<"

DRY_RUN=0
NO_RESTART=0
FORCE_PW_OFF=0

# Directives with no lockout risk — always applied.
HARDEN=(
  "PermitRootLogin no"
  "PermitEmptyPasswords no"
  "X11Forwarding no"
  "MaxAuthTries 4"
  "LoginGraceTime 30"
  "ClientAliveInterval 300"
  "ClientAliveCountMax 2"
)

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; s/^set -euo.*//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)            DRY_RUN=1 ;;
    --no-restart)         NO_RESTART=1 ;;
    --force-password-off) FORCE_PW_OFF=1 ;;
    -h|--help)            usage; exit 0 ;;
    *)                    die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

have_systemd() { [ -d /run/systemd/system ]; }

detect_sshd_bin() {
  if [ -n "$SSHD_BIN" ]; then printf '%s' "$SSHD_BIN"; return; fi
  local p
  for p in /usr/sbin/sshd /sbin/sshd "$(command -v sshd 2>/dev/null || true)"; do
    if [ -n "$p" ] && [ -x "$p" ]; then printf '%s' "$p"; return; fi
  done
  printf ''
}

# True if root or $SUDO_USER has at least one real public key installed.
has_authorized_keys() {
  local users=() u home akf
  [ -n "${SUDO_USER:-}" ] && users+=("$SUDO_USER")
  users+=("root")
  for u in "${users[@]}"; do
    home=$(getent passwd "$u" 2>/dev/null | cut -d: -f6 || true)
    [ -n "$home" ] || continue
    akf="$home/.ssh/authorized_keys"
    if [ -s "$akf" ] && grep -Eq '^[[:space:]]*(ssh-|ecdsa-|sk-|sntrup)' "$akf" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

main_has_include() {
  [ -f "$SSHD_CONFIG" ] || return 1
  # An active (uncommented) Include line that pulls in our drop-in directory.
  grep -Ei '^[[:space:]]*Include[[:space:]]' "$SSHD_CONFIG" | grep -Fq "$SSHD_CONFD_DIR"
}

# Decide PasswordAuthentication value.
if [ "$FORCE_PW_OFF" -eq 1 ]; then
  PW_VALUE="no"
elif has_authorized_keys; then
  PW_VALUE="no"
  ok "Key-based auth detected — will disable PasswordAuthentication."
else
  PW_VALUE="yes"
  warn "No authorized_keys for root or \$SUDO_USER. Leaving PasswordAuthentication ENABLED to avoid lockout."
  warn "Install a key (ssh-copy-id) and re-run with --force-password-off to turn it off."
fi

build_block() {
  local d
  for d in "${HARDEN[@]}"; do printf '%s\n' "$d"; done
  printf 'PasswordAuthentication %s\n' "$PW_VALUE"
}

show_intended() {
  log "Intended directives:"
  build_block | sed 's/^/    /'
}

backup_main() {
  [ -f "$SSHD_CONFIG" ] || return 0
  local ts bak
  ts=$(date +%Y%m%d%H%M%S)
  bak="${SSHD_CONFIG}.roboshield.bak.${ts}"
  cp -p "$SSHD_CONFIG" "$bak"
  ok "Backed up $SSHD_CONFIG -> $bak"
}

apply_dropin() {
  mkdir -p "$SSHD_CONFD_DIR"
  local f="$SSHD_CONFD_DIR/$DROPIN_NAME"
  {
    printf '%s\n' "$MARKER_BEGIN"
    printf '# Managed by RoboShield ssh_hardening.sh — do not edit by hand.\n'
    build_block
    printf '%s\n' "$MARKER_END"
  } >"$f.tmp"
  chmod 0644 "$f.tmp"
  mv "$f.tmp" "$f"
  ok "Wrote drop-in $f (sorts first, so it wins over later *.conf)."
}

apply_mainfile() {
  backup_main
  : >"${SSHD_CONFIG}.tmp"
  # Strip any previous RoboShield block, then comment out active managed keys.
  awk -v b="$MARKER_BEGIN" -v e="$MARKER_END" '
    $0==b {skip=1; next} $0==e {skip=0; next} skip!=1 {print}
  ' "$SSHD_CONFIG" >"${SSHD_CONFIG}.tmp"
  local d key
  for d in "${HARDEN[@]}" "PasswordAuthentication x"; do
    key=${d%% *}
    sed -i -E "s/^[[:space:]]*(${key}[[:space:]].*)$/# \\1  # superseded by RoboShield/I" "${SSHD_CONFIG}.tmp"
  done
  {
    printf '\n%s\n' "$MARKER_BEGIN"
    build_block
    printf '%s\n' "$MARKER_END"
  } >>"${SSHD_CONFIG}.tmp"
  mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
  ok "Updated $SSHD_CONFIG (no Include support detected; used a marked block)."
}

validate_config() {
  local bin; bin=$(detect_sshd_bin)
  [ -n "$bin" ] || { warn "sshd binary not found; skipping 'sshd -t'."; return 0; }
  local err; err=$(mktemp)
  if "$bin" -t -f "$SSHD_CONFIG" 2>"$err"; then
    ok "sshd -t: configuration is valid."
    rm -f "$err"
  else
    sed 's/^/    /' "$err" >&2; rm -f "$err"
    die "Invalid sshd config — NOT reloading. Your backup is intact."
  fi
}

reload_ssh() {
  local unit
  if have_systemd; then
    for unit in ssh sshd; do
      if systemctl cat "${unit}.service" >/dev/null 2>&1; then
        if systemctl reload "${unit}.service" 2>/dev/null \
           || systemctl restart "${unit}.service"; then
          ok "Reloaded ${unit}.service"; return 0
        fi
      fi
    done
  fi
  if command -v service >/dev/null 2>&1; then
    if service ssh reload 2>/dev/null || service ssh restart 2>/dev/null \
       || service sshd restart 2>/dev/null; then
      ok "Reloaded ssh via service(8)"; return 0
    fi
  fi
  warn "Could not reload SSH automatically (no systemd / no service control — common on WSL)."
  warn "Apply manually: sudo systemctl reload ssh   (or)   sudo service ssh reload"
}

verify_effective() {
  local bin; bin=$(detect_sshd_bin) eff_root="" eff_pw=""
  if [ -n "$bin" ] && "$bin" -T -f "$SSHD_CONFIG" >/tmp/roboshield_sshdT.$$ 2>/dev/null; then
    eff_root=$(awk 'tolower($1)=="permitrootlogin"{v=$2} END{print v}' /tmp/roboshield_sshdT.$$)
    eff_pw=$(awk 'tolower($1)=="passwordauthentication"{v=$2} END{print v}' /tmp/roboshield_sshdT.$$)
    rm -f /tmp/roboshield_sshdT.$$
    log "Effective PermitRootLogin       = ${eff_root:-<unset>}"
    log "Effective PasswordAuthentication = ${eff_pw:-<unset>}"
    if [ "${eff_root,,}" != "no" ]; then
      warn "PermitRootLogin is still '${eff_root}' in the RESOLVED config — something overrides us. Find it:"
      warn "  sudo grep -rniE '^[[:space:]]*PermitRootLogin' $SSHD_CONFIG $SSHD_CONFD_DIR/"
    fi
  else
    # No usable sshd binary (e.g. throwaway test config): textual check.
    rm -f /tmp/roboshield_sshdT.$$ 2>/dev/null || true
    log "Verifying written config textually (no sshd binary available):"
    grep -rniE '^[[:space:]]*PermitRootLogin' "$SSHD_CONFIG" "$SSHD_CONFD_DIR" 2>/dev/null \
      | sed 's/^/    /' || warn "No active PermitRootLogin line found."
  fi
}

# ---- main -------------------------------------------------------------------

if [ ! -f "$SSHD_CONFIG" ] && [ -z "$(detect_sshd_bin)" ]; then
  die "OpenSSH server not found ($SSHD_CONFIG missing and no sshd binary). Install openssh-server first."
fi

show_intended

if [ "$DRY_RUN" -eq 1 ]; then
  log "--dry-run: no files changed."
  if main_has_include; then log "Would write drop-in: $SSHD_CONFD_DIR/$DROPIN_NAME"
  else log "Would edit main file: $SSHD_CONFIG (no Include detected)"; fi
  exit 0
fi

# Need write access where we're about to write.
if main_has_include; then
  mkdir -p "$SSHD_CONFD_DIR" 2>/dev/null || true
  [ -w "$SSHD_CONFD_DIR" ] || die "Need write access to $SSHD_CONFD_DIR — run with sudo."
  apply_dropin
else
  [ -w "$SSHD_CONFIG" ] || die "Need write access to $SSHD_CONFIG — run with sudo."
  apply_mainfile
fi

if [ "$NO_RESTART" -eq 1 ]; then
  log "--no-restart: skipping validation and reload."
  verify_effective
  exit 0
fi

validate_config
reload_ssh
verify_effective
ok "Done."
