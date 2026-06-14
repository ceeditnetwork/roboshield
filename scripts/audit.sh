#!/bin/bash
echo "=== RoboShield Audit ==="
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
 echo "[PASS] Root login disabled"
else
 echo "[FAIL] Root login enabled"
fi
ss -tulnp
if command -v docker >/dev/null 2>&1; then
    echo
    echo "[INFO] Docker detected"
    bash ./scripts/docker_security_check.sh
fi
