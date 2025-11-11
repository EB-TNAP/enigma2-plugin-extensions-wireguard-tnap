#!/bin/sh
#
# WireGuard TNAP Server - Complete Uninstall Script
#
# This script completely removes the WireGuard VPN server installation.
# Use this if you want to install commercial WireGuard client plugins instead.
#
# What this script does:
# - Stops WireGuard service
# - Removes all configurations and keys
# - Removes init scripts and auto-start
# - Removes firewall rules
# - Uninstalls packages
# - Cleans up IP forwarding settings
#
# WARNING: This will delete your VPN keys and configurations!
# You will need to reconfigure all client devices if you reinstall.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Output functions
info() {
    echo "${BLUE}ℹ${NC} $1"
}

success() {
    echo "${GREEN}✓${NC} $1"
}

warning() {
    echo "${YELLOW}⚠${NC} $1"
}

error() {
    echo "${RED}✗${NC} $1"
}

header() {
    echo ""
    echo "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo "${BLUE}  $1${NC}"
    echo "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root"
    exit 1
fi

header "WireGuard TNAP Server - Complete Uninstall"

# Check if WireGuard is actually installed
if [ ! -f "/etc/wireguard/wg0.conf" ] && [ ! -f "/etc/init.d/wireguard" ]; then
    warning "WireGuard does not appear to be installed"
    info "Nothing to uninstall"
    exit 0
fi

# Step 1: Stop WireGuard service
header "Step 1: Stopping WireGuard Service"

if [ -f "/etc/init.d/wireguard" ]; then
    info "Stopping WireGuard service..."
    if /etc/init.d/wireguard stop 2>/dev/null; then
        success "WireGuard service stopped"
    else
        warning "Could not stop WireGuard service (may not be running)"
    fi
else
    info "WireGuard init script not found (already removed)"
fi

# Also try wg-quick if it's running
if wg-quick down wg0 2>/dev/null; then
    success "Stopped wg0 interface"
fi

# Step 2: Remove auto-start
header "Step 2: Removing Auto-Start Configuration"

if [ -f "/etc/init.d/wireguard" ]; then
    info "Removing auto-start links..."
    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d -f wireguard remove 2>/dev/null || true
        success "Removed auto-start (update-rc.d)"
    else
        # Manual removal of symlinks
        rm -f /etc/rc*.d/*wireguard 2>/dev/null || true
        success "Removed auto-start symlinks"
    fi
else
    info "No auto-start configuration found"
fi

# Step 3: Backup keys (optional safety measure)
header "Step 3: Backing Up Keys (Just in Case)"

if [ -d "/etc/wireguard" ]; then
    BACKUP_DIR="/tmp/wireguard-backup-$(date +%Y%m%d-%H%M%S)"
    info "Creating backup of keys to: ${BACKUP_DIR}"
    mkdir -p "${BACKUP_DIR}"
    cp -r /etc/wireguard/* "${BACKUP_DIR}/" 2>/dev/null || true
    success "Backup created at ${BACKUP_DIR}"
    warning "This backup will be lost on reboot (stored in /tmp)"
    warning "Copy to /media/hdd/ or USB if you want to keep it"
else
    info "No configurations found to backup"
fi

# Step 4: Remove WireGuard configurations and keys
header "Step 4: Removing WireGuard Configurations and Keys"

if [ -d "/etc/wireguard" ]; then
    info "Removing /etc/wireguard/ directory..."
    rm -rf /etc/wireguard
    success "Removed all WireGuard configurations and keys"
else
    info "Configuration directory already removed"
fi

# Step 5: Remove init script
header "Step 5: Removing Init Script"

if [ -f "/etc/init.d/wireguard" ]; then
    info "Removing /etc/init.d/wireguard..."
    rm -f /etc/init.d/wireguard
    success "Init script removed"
else
    info "Init script already removed"
fi

# Step 6: Remove firewall rules and IP forwarding
header "Step 6: Removing Firewall Rules"

info "Removing iptables NAT rules..."

# Find the main network interface (usually eth0)
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

if [ -n "$INTERFACE" ]; then
    # Remove NAT rule if it exists
    if iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$INTERFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o "$INTERFACE" -j MASQUERADE
        success "Removed NAT masquerading rule"
    else
        info "NAT rule not found (already removed or never set)"
    fi
else
    warning "Could not determine network interface"
fi

# Disable IP forwarding
info "Disabling IP forwarding..."
echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# Remove sysctl configuration
if [ -f "/etc/sysctl.d/99-wireguard.conf" ]; then
    rm -f /etc/sysctl.d/99-wireguard.conf
    success "Removed sysctl configuration"
fi

# Step 7: Unload kernel module
header "Step 7: Unloading Kernel Module"

if lsmod | grep -q wireguard; then
    info "Unloading WireGuard kernel module..."
    if rmmod wireguard 2>/dev/null; then
        success "Kernel module unloaded"
    else
        warning "Could not unload kernel module (may be in use or built-in)"
    fi
else
    info "Kernel module not loaded"
fi

# Step 8: Uninstall packages
header "Step 8: Uninstalling Packages"

info "Removing WireGuard packages..."

# Remove wireguard-tools
if opkg list-installed | grep -q "^wireguard-tools"; then
    info "Removing wireguard-tools package..."
    if opkg remove wireguard-tools 2>/dev/null; then
        success "wireguard-tools removed"
    else
        warning "Could not remove wireguard-tools"
    fi
else
    info "wireguard-tools not installed"
fi

# Remove kernel module package if present
if opkg list-installed | grep -q "^kernel-module-wireguard"; then
    info "Removing kernel-module-wireguard package..."
    if opkg remove kernel-module-wireguard 2>/dev/null; then
        success "kernel-module-wireguard removed"
    else
        warning "Could not remove kernel-module-wireguard"
    fi
else
    info "kernel-module-wireguard not installed (may be built-in)"
fi

# Step 9: Final cleanup
header "Step 9: Final Cleanup"

# Remove any leftover files
info "Checking for leftover files..."

# Remove backup configuration file we created
if [ -f "/etc/backup.cfg" ]; then
    # Only remove if it only contains WireGuard entries
    if grep -q "^/etc/init.d/wireguard$" /etc/backup.cfg && [ "$(wc -l < /etc/backup.cfg)" -le 10 ]; then
        rm -f /etc/backup.cfg
        success "Removed /etc/backup.cfg"
    else
        warning "/etc/backup.cfg exists but may contain other entries - not removing"
    fi
fi

# Remove post-restore script
if [ -f "/usr/script/wireguard-post-restore.sh" ]; then
    rm -f /usr/script/wireguard-post-restore.sh
    success "Removed /usr/script/wireguard-post-restore.sh"
fi

# Remove wg binary if it exists in custom locations
if [ -f "/usr/local/bin/wg" ]; then
    rm -f /usr/local/bin/wg
    success "Removed /usr/local/bin/wg"
fi

if [ -f "/usr/local/bin/wg-quick" ]; then
    rm -f /usr/local/bin/wg-quick
    success "Removed /usr/local/bin/wg-quick"
fi

# Check for any running WireGuard processes
if pgrep -x "wg" >/dev/null || pgrep -x "wg-quick" >/dev/null; then
    warning "WireGuard processes still running - killing them..."
    killall wg wg-quick 2>/dev/null || true
fi

success "Cleanup complete"

# Step 10: Summary
header "Uninstall Complete"

echo "${GREEN}WireGuard has been completely removed from your system!${NC}"
echo ""
echo "What was removed:"
echo "  • All VPN configurations and keys"
echo "  • Init scripts and auto-start"
echo "  • Firewall rules and IP forwarding"
echo "  • WireGuard packages"
echo ""
echo "What you can do now:"
echo "  • Install commercial WireGuard client plugins from feeds"
echo "  • Reinstall WireGuard TNAP Server (will generate new keys)"
echo "  • Keep using your receiver without VPN"
echo ""

if [ -d "${BACKUP_DIR}" ]; then
    echo "${YELLOW}Temporary backup of your keys:${NC}"
    echo "  ${BACKUP_DIR}"
    echo "  ${YELLOW}(Will be deleted on reboot - copy to USB/HDD if needed)${NC}"
    echo ""
fi

echo "${BLUE}Note:${NC} If you have AutoBackup enabled in TNAP, it may still have"
echo "      backed up copies of your old WireGuard configuration."
echo ""

success "You can now close this window"

exit 0
