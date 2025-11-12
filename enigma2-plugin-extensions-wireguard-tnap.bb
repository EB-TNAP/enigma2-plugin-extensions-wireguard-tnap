SUMMARY = "WireGuard VPN Self-Hosted Server for TNAP"
DESCRIPTION = "Easy-to-use WireGuard VPN server setup plugin. \
Allows you to create your own VPN server on your receiver for secure remote access. \
Includes automatic setup, key generation, and configuration. \
NOTE: This is the free, self-hosted WireGuard server. \
Cannot be installed alongside commercial WireGuard client plugins."
HOMEPAGE = "https://tnapimages.com"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
SECTION = "base"
PRIORITY = "optional"

# Version and revision
PV = "4.0"
PR = "r0"

require conf/license/license-gplv2.inc

inherit allarch

DEPENDS = "python3"

# CRITICAL: Cannot coexist with Firewall plugin (conflicting security models)
RCONFLICTS:${PN} = "enigma2-plugin-security-firewall"

# Core dependencies (required)
RDEPENDS:${PN} = "python3-core wireguard-tools"

# Recommended packages (installed if available, not fatal if missing)
# Kernel modules are kernel-version-specific, so we recommend rather than require
# The installer script (wireguard-install.sh) will install these at runtime via opkg
RRECOMMENDS:${PN} = " \
    enigma2-plugin-extensions-autobackup \
    kernel-module-wireguard \
    kernel-module-udp-tunnel \
    kernel-module-ip6-udp-tunnel \
    kernel-module-iptable-mangle \
    kernel-module-iptable-nat \
    kernel-module-xt-tcpmss \
    kernel-module-xt-tcpudp \
    kernel-module-xt-masquerade \
    kernel-module-nf-nat \
    iptables-module-ip6t-reject \
    kernel-module-nf-reject-ipv6 \
"

# Conflicts with paid WireGuard plugins and Firewall plugin (both provide port protection)
RCONFLICTS:${PN} = "enigma2-plugin-extensions-wireguard enigma2-plugin-security-firewall"

SRC_URI = " \
    file://plugin.py \
    file://__init__.py \
    file://wireguard-install.sh \
    file://wireguard-uninstall.sh \
    file://wireguard-post-restore.sh \
"

S = "${WORKDIR}"

do_install() {
    # Install plugin files
    install -d ${D}${libdir}/enigma2/python/Plugins/Extensions/WireGuardTNAP
    install -m 0644 ${WORKDIR}/plugin.py ${D}${libdir}/enigma2/python/Plugins/Extensions/WireGuardTNAP/
    install -m 0644 ${WORKDIR}/__init__.py ${D}${libdir}/enigma2/python/Plugins/Extensions/WireGuardTNAP/
    install -m 0755 ${WORKDIR}/wireguard-install.sh ${D}${libdir}/enigma2/python/Plugins/Extensions/WireGuardTNAP/
    install -m 0755 ${WORKDIR}/wireguard-uninstall.sh ${D}${libdir}/enigma2/python/Plugins/Extensions/WireGuardTNAP/

    # Install post-restore script to /usr/script/ (executed by AutoBackup's /etc/autoinstall)
    install -d ${D}/usr/script
    install -m 0755 ${WORKDIR}/wireguard-post-restore.sh ${D}/usr/script/
}

FILES:${PN} = " \
    ${libdir}/enigma2/python/Plugins/Extensions/WireGuardTNAP/* \
    /usr/script/wireguard-post-restore.sh \
"

# This plugin provides both Extensions and SystemPlugins functionality
PACKAGES = "${PN}"

# Plugin metadata for Enigma2
ENIGMA2_PLUGIN_NAME = "WireGuard TNAP Server"

pkg_prerm:${PN}() {
#!/bin/sh
# Pre-removal script - runs before package files are deleted
# Stop WireGuard service and clean up iptables rules

echo "Stopping WireGuard TNAP Server plugin..."

# Stop WireGuard interface if running
if [ -x "$(which wg-quick)" ] && [ -f /etc/wireguard/wg0.conf ]; then
	echo "Stopping wg0 interface..."
	wg-quick down wg0 2>/dev/null || true
fi

# Remove iptables NAT rules for WireGuard (these are added by PostUp in wg0.conf)
if [ -x "$(which iptables)" ]; then
	echo "Removing WireGuard iptables rules..."

	# Get network interface (same logic as installer)
	NET_IFACE=$(ip link show | grep -v "lo:" | grep "state UP" | head -n 1 | awk -F: '{print $2}' | tr -d ' ')

	if [ -n "$NET_IFACE" ]; then
		# Remove MASQUERADE rule
		iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NET_IFACE -j MASQUERADE 2>/dev/null || true

		# Remove port blocking rules (if they exist)
		iptables -D INPUT -p tcp --dport 80 -i $NET_IFACE -j DROP 2>/dev/null || true
		iptables -D INPUT -p tcp --dport 8080 -i $NET_IFACE -j DROP 2>/dev/null || true
		iptables -D INPUT -p tcp --dport 8001 -i $NET_IFACE -j DROP 2>/dev/null || true
		iptables -D INPUT -p tcp --dport 8002 -i $NET_IFACE -j DROP 2>/dev/null || true
		iptables -D INPUT -p tcp --dport 8003 -i $NET_IFACE -j DROP 2>/dev/null || true
		iptables -D INPUT -p tcp --dport 23 -i $NET_IFACE -j DROP 2>/dev/null || true
		iptables -D INPUT -p tcp --dport 21 -i $NET_IFACE -j DROP 2>/dev/null || true
		iptables -D INPUT -p tcp --dport 873 -i $NET_IFACE -j DROP 2>/dev/null || true
	fi

	echo "WireGuard iptables rules removed."
fi

# Disable IP forwarding if WireGuard was using it
if [ -f /proc/sys/net/ipv4/ip_forward ]; then
	echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
fi

echo "WireGuard TNAP Server services stopped."
}

pkg_postrm:${PN}() {
#!/bin/sh
# Post-removal script - runs after package files are deleted
# Clean up configuration files, keys, and runtime files

echo "Cleaning up WireGuard TNAP Server plugin..."

# NOTE: /etc/wireguard is preserved during upgrades and removals
# This ensures VPN keys are not lost during package operations
if [ -d /etc/wireguard ]; then
	echo "Preserving /etc/wireguard configuration and keys"
	echo "NOTE: VPN configurations and keys have been preserved"
	echo "NOTE: To completely remove WireGuard configs, manually run: rm -rf /etc/wireguard"
else
	echo "NOTE: No WireGuard configurations found to preserve"
fi

# Remove post-restore script (installed to /usr/script/)
rm -f /usr/script/wireguard-post-restore.sh 2>/dev/null || true

# Remove Python cache files (if any remain)
rm -rf /usr/lib/enigma2/python/Plugins/Extensions/WireGuardTNAP/__pycache__ 2>/dev/null || true
rm -f /usr/lib/enigma2/python/Plugins/Extensions/WireGuardTNAP/*.pyc 2>/dev/null || true
rm -f /usr/lib/enigma2/python/Plugins/Extensions/WireGuardTNAP/*.pyo 2>/dev/null || true

# Remove plugin directory if empty
rmdir /usr/lib/enigma2/python/Plugins/Extensions/WireGuardTNAP 2>/dev/null || true

# Kill any remaining WireGuard processes
pkill -f "wg-quick" 2>/dev/null || true

echo "WireGuard TNAP Server plugin cleanup complete."
}
