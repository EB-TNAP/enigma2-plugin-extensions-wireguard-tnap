#!/bin/sh
#
# WireGuard Backup Helper Script
#
# This script copies the WireGuard IPK to backup locations for testing/development.
# Once the plugin is in feeds, this is not needed - autoinstall will handle it.
#
# Usage: Run this after building to copy IPK to backup folder for manual testing

PLUGIN_NAME="enigma2-plugin-extensions-wireguard-tnap"
BACKUP_LOCATIONS="/media/hdd/backup /media/usb/backup /media/mmc/backup"

echo "=== WireGuard Backup Helper (Development/Testing) ==="
echo ""
echo "This helper copies the WireGuard IPK to backup folders."
echo "Note: Once plugin is in feeds, this is automatic."
echo ""

# Find built IPK files in the deploy directory
IPK_PATTERN="/tmp/deploy/ipk/*/${PLUGIN_NAME}_*.ipk"
FOUND_IPK=""

for ipk in $IPK_PATTERN; do
    if [ -f "$ipk" ]; then
        FOUND_IPK="$ipk"
        echo "Found IPK: $ipk"
        break
    fi
done

if [ -z "$FOUND_IPK" ]; then
    echo "ERROR: Could not find built IPK file"
    echo "Expected location: /tmp/deploy/ipk/*/${PLUGIN_NAME}_*.ipk"
    echo ""
    echo "Build the package first with: bitbake $PLUGIN_NAME"
    exit 1
fi

# Copy to all backup locations
COPIED=0
for backup_dir in $BACKUP_LOCATIONS; do
    if [ -d "$backup_dir" ]; then
        echo ""
        echo "Copying to: $backup_dir"
        cp "$FOUND_IPK" "$backup_dir/" 2>/dev/null && {
            echo "  ✓ Copied successfully"
            COPIED=1
        } || echo "  ✗ Failed to copy"
    fi
done

if [ $COPIED -eq 0 ]; then
    echo ""
    echo "WARNING: No backup directories found!"
    echo "Searched: $BACKUP_LOCATIONS"
    echo ""
    echo "Solution: Insert USB drive or mount HDD, then create backup with AutoBackup plugin"
fi

echo ""
echo "=== Helper Complete ==="
echo ""
echo "Next steps for manual testing:"
echo "1. Flash new image"
echo "2. Boot and let AutoBackup restore settings"
echo "3. WireGuard will auto-install from backup folder IPK"
echo "4. WireGuard will auto-start with restored keys"
echo ""

exit 0
