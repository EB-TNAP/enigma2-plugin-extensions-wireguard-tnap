#!/bin/sh
#
# WireGuard Post-Restore Activation Script
#
# This script runs after AutoBackup restores WireGuard configurations
# to ensure WireGuard is properly activated with all necessary settings.
#
# Place this in /etc/init.d/ or call from autoinstall script
#

# Check if WireGuard config exists (was restored)
if [ ! -f "/etc/wireguard/wg0.conf" ]; then
    # No WireGuard configuration found, nothing to activate
    exit 0
fi

echo "WireGuard configuration detected - activating..."

# 1. Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

# 2. Load WireGuard kernel module if needed
if ! lsmod | grep -q wireguard; then
    modprobe wireguard 2>/dev/null || true
fi

# 3. Make init script executable if it was restored
if [ -f "/etc/init.d/wireguard" ]; then
    chmod +x /etc/init.d/wireguard

    # Enable auto-start
    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d wireguard defaults >/dev/null 2>&1
    fi

    # Start WireGuard
    /etc/init.d/wireguard start >/dev/null 2>&1

    echo "WireGuard activated successfully!"
else
    echo "Warning: /etc/init.d/wireguard not found - WireGuard may not start automatically"

    # Try to start WireGuard directly with wg-quick
    if command -v wg-quick >/dev/null 2>&1; then
        wg-quick up wg0 >/dev/null 2>&1 && echo "WireGuard started with wg-quick"
    fi
fi

exit 0
