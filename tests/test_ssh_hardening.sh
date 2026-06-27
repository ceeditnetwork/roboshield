#!/usr/bin/env bash
#
# test_ssh_hardening.sh — exercises ssh_hardening.sh against throwaway configs.
# Touches nothing under /etc, needs no root, never restarts a service.
# Run from the same directory as ssh_hardening.sh:  bash test_ssh_hardening.sh
#
set -u
HARDEN_SCRIPT="${1:-./ssh_hardening.sh}"
[ -f "$HARDEN_SCRIPT" ] || { echo "cannot find $HARDEN_SCRIPT"; exit 1; }

PASS=0; FAIL=0
check() { # check "label" "expected_regex" "file"
  if grep -Eq "$2" "$3"; then echo "  PASS: $1"; PASS=$((PASS+1));
  else echo "  FAIL: $1"; echo "    (expected /$2/ in $3)"; FAIL=$((FAIL+1)); fi
}
nocheck() { # must NOT match
  if grep -Eq "$2" "$3"; then echo "  FAIL: $1"; echo "    (did NOT expect /$2/ in $3)"; FAIL=$((FAIL+1));
  else echo "  PASS: $1"; PASS=$((PASS+1)); fi
}

run() { # run <cfg> <confd> <logfile> [extra flags...]
  local cfg="$1" confd="$2" logf="$3"; shift 3
  SSHD_CONFIG="$cfg" SSHD_CONFD_DIR="$confd" SSHD_BIN="/nonexistent/sshd" \
    bash "$HARDEN_SCRIPT" --no-restart "$@" >"$logf.log" 2>&1 || true
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "=============================================================="
echo " TEST 1: explicitly enabled root login, no Include (the old bug)"
echo "=============================================================="
T1="$WORK/t1"; mkdir -p "$T1/confd"
printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' >"$T1/sshd_config"
run "$T1/sshd_config" "$T1/confd" "$T1/out"
echo "--- resulting sshd_config ---"; sed 's/^/    /' "$T1/sshd_config"
nocheck "no active 'PermitRootLogin yes' remains" '^[[:space:]]*PermitRootLogin[[:space:]]+yes' "$T1/sshd_config"
check   "active 'PermitRootLogin no' present"      '^PermitRootLogin no'                          "$T1/sshd_config"
check   "old 'yes' line was commented out"         '^# *PermitRootLogin yes'                       "$T1/sshd_config"

echo
echo "=============================================================="
echo " TEST 2: Ubuntu-style Include present -> drop-in path"
echo "=============================================================="
T2="$WORK/t2"; mkdir -p "$T2/confd"
printf 'Include %s/*.conf\nPermitRootLogin yes\n' "$T2/confd" >"$T2/sshd_config"
run "$T2/sshd_config" "$T2/confd" "$T2/out"
DROPIN="$T2/confd/00-roboshield-hardening.conf"
[ -f "$DROPIN" ] && { echo "--- drop-in written ---"; sed 's/^/    /' "$DROPIN"; }
check "drop-in file created"                  '.' "$DROPIN"
check "drop-in disables root login"           '^PermitRootLogin no' "$DROPIN"
nocheck "main file left untouched by us"      'RoboShield' "$T2/sshd_config"

echo
echo "=============================================================="
echo " TEST 3: keyless host -> PasswordAuthentication must stay yes"
echo "=============================================================="
T3="$WORK/t3"; mkdir -p "$T3/confd"
printf 'PermitRootLogin yes\n' >"$T3/sshd_config"
# Force no-key path: empty HOME/SUDO_USER so has_authorized_keys finds nothing.
SUDO_USER="" HOME="$WORK/emptyhome" \
  SSHD_CONFIG="$T3/sshd_config" SSHD_CONFD_DIR="$T3/confd" SSHD_BIN="/nonexistent/sshd" \
  bash "$HARDEN_SCRIPT" --no-restart >"$T3/out.log" 2>&1 || true
echo "--- resulting sshd_config ---"; sed 's/^/    /' "$T3/sshd_config"
check   "root login still disabled even keyless" '^PermitRootLogin no'              "$T3/sshd_config"
check   "PasswordAuthentication kept yes (anti-lockout)" '^PasswordAuthentication yes' "$T3/sshd_config"
grep -q 'avoid lockout' "$T3/out.log" && echo "  PASS: emitted lockout warning" && PASS=$((PASS+1)) \
  || { echo "  FAIL: no lockout warning"; FAIL=$((FAIL+1)); }

echo
echo "=============================================================="
echo " TEST 4: --force-password-off overrides the guard"
echo "=============================================================="
T4="$WORK/t4"; mkdir -p "$T4/confd"
printf 'PermitRootLogin yes\n' >"$T4/sshd_config"
run "$T4/sshd_config" "$T4/confd" "$T4/out" --force-password-off
check "PasswordAuthentication forced no" '^PasswordAuthentication no' "$T4/sshd_config"

echo
echo "=============================================================="
echo " TEST 5: idempotency — run twice, no duplicate active lines"
echo "=============================================================="
T5="$WORK/t5"; mkdir -p "$T5/confd"
printf 'PermitRootLogin yes\n' >"$T5/sshd_config"
run "$T5/sshd_config" "$T5/confd" "$T5/out1" --force-password-off
run "$T5/sshd_config" "$T5/confd" "$T5/out2" --force-password-off
N=$(grep -Ec '^PermitRootLogin no' "$T5/sshd_config")
echo "    active 'PermitRootLogin no' lines after 2 runs: $N"
[ "$N" -eq 1 ] && { echo "  PASS: exactly one active line"; PASS=$((PASS+1)); } \
                || { echo "  FAIL: expected 1, got $N"; FAIL=$((FAIL+1)); }

echo
echo "=============================================================="
echo " TEST 6: --dry-run changes nothing"
echo "=============================================================="
T6="$WORK/t6"; mkdir -p "$T6/confd"
printf 'PermitRootLogin yes\n' >"$T6/sshd_config"
BEFORE=$(md5sum "$T6/sshd_config" | awk '{print $1}')
run "$T6/sshd_config" "$T6/confd" "$T6/out" --dry-run
AFTER=$(md5sum "$T6/sshd_config" | awk '{print $1}')
[ "$BEFORE" = "$AFTER" ] && { echo "  PASS: file unchanged"; PASS=$((PASS+1)); } \
                          || { echo "  FAIL: file modified"; FAIL=$((FAIL+1)); }

echo
echo "=============================================================="
echo " RESULT: $PASS passed, $FAIL failed"
echo "=============================================================="
[ "$FAIL" -eq 0 ]
