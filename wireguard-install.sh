#!/bin/sh
# WireGuard VPN Complete Installer for TNAP/Enigma2
# Version: 4.0
# URL: https://tnapimages.com/wireguard-install.sh
#
# ONE-LINE INSTALL:
# wget -qO- https://tnapimages.com/wireguard-install.sh | sh
# OR:
# curl -sSL https://tnapimages.com/wireguard-install.sh | sh

set -e

VERSION="4.0"
WGDIR="/etc/wireguard"
LOGFILE="/tmp/wireguard-install.log"

# Ensure PATH includes common sbin directories for iptables, ip, etc.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOGFILE"
}

error() {
    echo "${RED}[ERROR]${NC} $1"
    log "ERROR: $1"
    exit 1
}

success() {
    echo "${GREEN}[SUCCESS]${NC} $1"
    log "SUCCESS: $1"
}

warning() {
    echo "${YELLOW}[WARNING]${NC} $1"
    log "WARNING: $1"
}

info() {
    echo "${BLUE}[INFO]${NC} $1"
    log "INFO: $1"
}

banner() {
    clear
    echo "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo "${BLUE}    WireGuard VPN Complete Installer v${VERSION}${NC}"
    echo "${BLUE}    Primary: TNAP | Compatible: Most Enigma2 Receivers${NC}"
    echo "${BLUE}    https://tnapimages.com${NC}"
    echo "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

install_wireguard_packages() {
    info "Installing WireGuard packages..."

    # Update package lists
    info "Updating package lists..."
    opkg update >/dev/null 2>&1 || warning "opkg update failed"

    # Install iptables if not present (required for WireGuard)
    if ! command -v iptables >/dev/null 2>&1; then
        info "Installing iptables (required for WireGuard)..."
        if opkg install iptables 2>/dev/null; then
            success "iptables installed"
        else
            error "Failed to install iptables. Check internet connection and package feeds."
        fi
    else
        success "iptables already installed"
    fi

    # Install WireGuard tools
    if ! command -v wg >/dev/null 2>&1; then
        info "Installing wireguard-tools..."
        if opkg install wireguard-tools 2>/dev/null; then
            success "wireguard-tools installed"
        else
            error "Failed to install wireguard-tools. Check internet connection and package feeds."
        fi
    else
        success "wireguard-tools already installed"
    fi

    # Install WireGuard kernel module (if available as separate package)
    if ! lsmod | grep -q wireguard; then
        info "Checking for kernel-module-wireguard package..."
        if opkg install kernel-module-wireguard 2>/dev/null; then
            success "kernel-module-wireguard installed"
            # Load the module
            if modprobe wireguard 2>/dev/null; then
                success "WireGuard kernel module loaded"
            else
                warning "Could not load wireguard module (may be built-in to kernel)"
            fi
        else
            warning "kernel-module-wireguard package not available (WireGuard may be built into kernel)"
            # Try to load module anyway (might be built-in or already present)
            if modprobe wireguard 2>/dev/null; then
                success "WireGuard kernel support detected (built-in)"
            else
                warning "WireGuard kernel module not found - may not be supported on this kernel"
            fi
        fi
    else
        success "WireGuard kernel module already loaded"
    fi
}

check_requirements() {
    info "Checking system requirements..."

    # Check if running as root
    if [ "$(id -u)" != "0" ]; then
        error "This script must be run as root"
    fi

    # Check kernel version
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    info "Kernel version: $KERNEL_VERSION"

    # Check if iptables is installed (not fatal - will install later)
    if ! command -v iptables >/dev/null 2>&1; then
        warning "iptables not found, will attempt to install..."
    fi

    # Check if WireGuard tools are installed
    if ! command -v wg >/dev/null 2>&1; then
        warning "WireGuard tools not found, will attempt to install..."
    fi

    # Check if WireGuard kernel module is available
    if ! modprobe wireguard 2>/dev/null; then
        if ! lsmod | grep -q wireguard; then
            warning "WireGuard kernel module not loaded, will attempt to install..."
        fi
    fi

    success "Requirements check complete"
}

check_internet() {
    info "Checking internet connection..."
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        success "Internet connection OK"
    else
        warning "No internet connection detected (may cause issues with opkg)"
    fi
}

install_optional_dependencies() {
    info "Checking optional dependencies..."

    # Update package lists
    info "Updating package lists..."
    opkg update >/dev/null 2>&1 || warning "opkg update failed"

    # Install iptables mangle module (required for MSS clamping)
    info "Installing iptables mangle module for MSS clamping..."
    if opkg install kernel-module-iptable-mangle 2>/dev/null; then
        success "iptable-mangle module installed"
        modprobe iptable_mangle 2>/dev/null || true
    else
        warning "Could not install iptable-mangle (MSS clamping will be disabled)"
    fi

    # Install TCPMSS module (required for MSS clamping)
    info "Installing TCPMSS module for MSS clamping..."
    if opkg install kernel-module-xt-tcpmss 2>/dev/null; then
        success "xt-tcpmss module installed"
        modprobe xt_TCPMSS 2>/dev/null || true
    else
        warning "Could not install xt-tcpmss (MSS clamping will be disabled)"
    fi

    # Install xt-tcpudp if TNAP firewall plugin is detected
    if [ -f /etc/init.d/firewall ]; then
        info "TNAP firewall plugin detected, installing kernel-module-xt-tcpudp..."
        opkg install kernel-module-xt-tcpudp 2>/dev/null && \
            success "xt-tcpudp module installed" || \
            warning "Could not install xt-tcpudp (may already be installed or unavailable)"
    else
        info "No TNAP firewall detected (this is normal for non-TNAP images)"
    fi

    # Install IPv6 REJECT support (for better error responses)
    info "Installing IPv6 REJECT module for proper connection refusal..."
    if opkg install iptables-module-ip6t-reject 2>/dev/null; then
        success "IPv6 REJECT module installed"
        modprobe nf_reject_ipv6 2>/dev/null || true
        modprobe ip6t_REJECT 2>/dev/null || true
    else
        warning "Could not install IPv6 REJECT module (will use DROP instead)"
    fi
}

generate_keys() {
    info "Generating WireGuard keys..."

    mkdir -p "$WGDIR"
    cd "$WGDIR"

    # Generate server keys
    if [ ! -f "server_private.key" ]; then
        wg genkey | tee server_private.key | wg pubkey > server_public.key
        chmod 600 server_private.key
        success "Server keys generated"
    else
        warning "Server keys already exist, skipping generation"
    fi

    # Generate client keys
    if [ ! -f "client_private.key" ]; then
        wg genkey | tee client_private.key | wg pubkey > client_public.key
        chmod 600 client_private.key
        success "Client keys generated"
    else
        warning "Client keys already exist, skipping generation"
    fi

    # Read keys
    SERVER_PRIVATE=$(cat server_private.key 2>/dev/null)
    SERVER_PUBLIC=$(cat server_public.key 2>/dev/null)
    CLIENT_PRIVATE=$(cat client_private.key 2>/dev/null)
    CLIENT_PUBLIC=$(cat client_public.key 2>/dev/null)

    # Validate keys are not empty - if any are empty, regenerate ALL keys
    if [ -z "$SERVER_PRIVATE" ] || [ -z "$SERVER_PUBLIC" ] || [ -z "$CLIENT_PRIVATE" ] || [ -z "$CLIENT_PUBLIC" ]; then
        error "Key files are missing or empty! Regenerating all keys..."
        rm -f server_private.key server_public.key client_private.key client_public.key 2>/dev/null

        # Regenerate server keys
        wg genkey | tee server_private.key | wg pubkey > server_public.key
        chmod 600 server_private.key
        success "Server keys regenerated"

        # Regenerate client keys
        wg genkey | tee client_private.key | wg pubkey > client_public.key
        chmod 600 client_private.key
        success "Client keys regenerated"

        # Re-read keys
        SERVER_PRIVATE=$(cat server_private.key)
        SERVER_PUBLIC=$(cat server_public.key)
        CLIENT_PRIVATE=$(cat client_private.key)
        CLIENT_PUBLIC=$(cat client_public.key)

        # Final validation
        if [ -z "$SERVER_PRIVATE" ] || [ -z "$SERVER_PUBLIC" ] || [ -z "$CLIENT_PRIVATE" ] || [ -z "$CLIENT_PUBLIC" ]; then
            error "FATAL: Unable to generate valid keys! Check wg-quick installation."
            exit 1
        fi
    fi
}

detect_network_interface() {
    # Try to detect primary network interface (works on most receivers)
    for iface in eth0 eth1 wlan0 br0; do
        if ip link show "$iface" >/dev/null 2>&1; then
            echo "$iface"
            return 0
        fi
    done

    # Fallback: get first non-loopback interface
    ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | head -n1
}

get_network_info() {
    info "Detecting network configuration..."

    # Detect network interface
    NET_IFACE=$(detect_network_interface)
    if [ -z "$NET_IFACE" ]; then
        error "Could not detect network interface"
    fi
    info "Network interface: $NET_IFACE"

    # Get local IP (try multiple methods for compatibility)
    LOCAL_IP=$(ip -4 addr show "$NET_IFACE" 2>/dev/null | grep inet | awk '{print $2}' | cut -d'/' -f1)
    if [ -z "$LOCAL_IP" ]; then
        LOCAL_IP=$(ifconfig "$NET_IFACE" 2>/dev/null | grep 'inet addr:' | sed -e 's/.*inet addr:\([^ ]*\).*/\1/')
    fi
    if [ -z "$LOCAL_IP" ]; then
        LOCAL_IP=$(ifconfig "$NET_IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | sed 's/addr://')
    fi

    if [ -z "$LOCAL_IP" ]; then
        error "Could not detect local IP address for interface $NET_IFACE"
    fi

    info "Local IP: $LOCAL_IP"

    # Auto-detect local network range based on IP address
    case "$LOCAL_IP" in
        192.168.*)
            LOCAL_NETWORK="192.168.0.0/16"
            ;;
        10.*)
            LOCAL_NETWORK="10.0.0.0/8"
            ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)
            LOCAL_NETWORK="172.16.0.0/12"
            ;;
        *)
            # Unknown network - use /24 subnet
            LOCAL_NETWORK="${LOCAL_IP%.*}.0/24"
            ;;
    esac
    info "Local network: $LOCAL_NETWORK"

    # Try to get public IP (use APIs that return plain text)
    PUBLIC_IP=$(wget -qO- https://api.ipify.org 2>/dev/null || wget -qO- https://icanhazip.com 2>/dev/null || curl -s https://api.ipify.org 2>/dev/null || curl -s https://icanhazip.com 2>/dev/null || echo "")

    if [ -n "$PUBLIC_IP" ]; then
        info "Public IP: $PUBLIC_IP"
    else
        warning "Could not auto-detect public IP"
        PUBLIC_IP="YOUR_PUBLIC_IP_HERE"
    fi
}

create_server_config() {
    info "Creating server configuration..."

    # Backup existing wg0.conf if it exists (upgrade scenario)
    if [ -f "$WGDIR/wg0.conf" ]; then
        BACKUP_FILE="$WGDIR/wg0.conf.backup-$(date +%Y%m%d-%H%M%S)"
        cp "$WGDIR/wg0.conf" "$BACKUP_FILE"
        info "Existing config backed up to: $BACKUP_FILE"
    fi

    # Check if MSS clamping modules are available
    MSS_AVAILABLE=false
    if lsmod | grep -q iptable_mangle && lsmod | grep -q xt_TCPMSS; then
        MSS_AVAILABLE=true
        info "MSS clamping modules available - enabling for smooth streaming"
    else
        warning "MSS clamping modules not available - using MTU optimization only"
    fi

    # Check if xt_tcpudp module is available for port-based firewall rules
    TCPUDP_AVAILABLE=false
    if lsmod | grep -q xt_tcpudp || modprobe xt_tcpudp 2>/dev/null; then
        TCPUDP_AVAILABLE=true
        info "TCP/UDP match module available - enabling port-based firewall rules"
    else
        warning "TCP/UDP match module not available - skipping port-based firewall rules"
        warning "Note: Install firewall plugin or kernel-module-xt-tcpudp for enhanced security"
    fi

    # Create base config
    cat > "$WGDIR/wg0.conf" << EOF
[Interface]
# WireGuard VPN Server Configuration
# Generated by TNAP WireGuard Installer v${VERSION}
# Date: $(date)
# Receiver: $(hostname)
# Network Interface: ${NET_IFACE}
#
# IMPORTANT: Keys are read from files at boot time!
# This allows keys to be replaced without reinstalling.
# Key files: server_private.key, client_public.key

Address = 10.99.99.1/24
ListenPort = 51820
MTU = 1420

# Private key is read from file at service start
# This allows key replacement without reconfiguration
PostUp = wg set %i private-key ${WGDIR}/server_private.key
EOF

    # Add port-based firewall rules if xt_tcpudp module is available
    if [ "$TCPUDP_AVAILABLE" = "true" ]; then
        cat >> "$WGDIR/wg0.conf" << 'EOF'

# SECURITY: Block external access to OpenWebif, streaming, and transcoding ports
# Only allow access from VPN (wg0) and local network (${LOCAL_NETWORK})
PostUp = iptables -I INPUT -p tcp --dport 80 -i ${NET_IFACE} -j DROP
PostUp = iptables -I INPUT -p tcp --dport 8080 -i ${NET_IFACE} -j DROP
PostUp = iptables -I INPUT -p tcp --dport 8001 -i ${NET_IFACE} -j DROP
PostUp = iptables -I INPUT -p tcp --dport 8002 -i ${NET_IFACE} -j DROP
PostUp = iptables -I INPUT -p tcp --dport 8003 -i ${NET_IFACE} -j DROP
PostUp = iptables -I INPUT -p tcp --dport 80 -i %i -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 8080 -i %i -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 8001 -i %i -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 8002 -i %i -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 8003 -i %i -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 80 -s ${LOCAL_NETWORK} -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 8080 -s ${LOCAL_NETWORK} -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 8001 -s ${LOCAL_NETWORK} -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 8002 -s ${LOCAL_NETWORK} -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 8003 -s ${LOCAL_NETWORK} -j ACCEPT

# SECURITY CLEANUP: Remove firewall rules on shutdown (reverse order of PostUp)
PostDown = iptables -D INPUT -p tcp --dport 8003 -s ${LOCAL_NETWORK} -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 8002 -s ${LOCAL_NETWORK} -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 8001 -s ${LOCAL_NETWORK} -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 8080 -s ${LOCAL_NETWORK} -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 80 -s ${LOCAL_NETWORK} -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 8003 -i %i -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 8002 -i %i -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 8001 -i %i -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 8080 -i %i -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 80 -i %i -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 8003 -i ${NET_IFACE} -j DROP
PostDown = iptables -D INPUT -p tcp --dport 8002 -i ${NET_IFACE} -j DROP
PostDown = iptables -D INPUT -p tcp --dport 8001 -i ${NET_IFACE} -j DROP
PostDown = iptables -D INPUT -p tcp --dport 8080 -i ${NET_IFACE} -j DROP
PostDown = iptables -D INPUT -p tcp --dport 80 -i ${NET_IFACE} -j DROP
EOF
        # Replace variables in the appended section (use | delimiter to avoid issues with / in CIDR notation)
        sed -i "s|\${NET_IFACE}|${NET_IFACE}|g" "$WGDIR/wg0.conf"
        sed -i "s|\${LOCAL_NETWORK}|${LOCAL_NETWORK}|g" "$WGDIR/wg0.conf"

        # Add IPv6 protection (block ALL external IPv6 access to protect against future threats)
        cat >> "$WGDIR/wg0.conf" << 'EOF'

# IPv6 SECURITY: Block all external IPv6 access to sensitive ports
# Protects against current and future IPv6-based attacks
PostUp = ip6tables -I INPUT -p tcp --dport 80 -j DROP 2>/dev/null || true
PostUp = ip6tables -I INPUT -p tcp --dport 8080 -j DROP 2>/dev/null || true
PostUp = ip6tables -I INPUT -p tcp --dport 8001 -j DROP 2>/dev/null || true
PostUp = ip6tables -I INPUT -p tcp --dport 8002 -j DROP 2>/dev/null || true
PostUp = ip6tables -I INPUT -p tcp --dport 8003 -j DROP 2>/dev/null || true
PostUp = ip6tables -I INPUT -p tcp --dport 23 -j DROP 2>/dev/null || true
PostUp = ip6tables -I INPUT -p tcp --dport 21 -j DROP 2>/dev/null || true

# IPv6 SECURITY CLEANUP: Remove on shutdown (reverse order)
PostDown = ip6tables -D INPUT -p tcp --dport 21 -j DROP 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 23 -j DROP 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 8003 -j DROP 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 8002 -j DROP 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 8001 -j DROP 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 8080 -j DROP 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 80 -j DROP 2>/dev/null || true
EOF
    else
        cat >> "$WGDIR/wg0.conf" << 'EOF'

# NOTE: Port-based firewall rules disabled (xt_tcpudp kernel module not available)
# RECOMMENDATION: Install firewall plugin for comprehensive security
# Alternative: Manually configure your firewall to protect ports 80, 8080, 8001, 8002, 8003
EOF
    fi

    # Continue with base config
    cat >> "$WGDIR/wg0.conf" << 'EOF'
EOF

    # Add MSS clamping rules if modules are available
    if [ "$MSS_AVAILABLE" = "true" ]; then
        cat >> "$WGDIR/wg0.conf" << 'EOF'

# MSS clamping for smooth streaming through VPN (prevents packet fragmentation)
PostUp = iptables -t mangle -A FORWARD -i %i -o ${NET_IFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = iptables -t mangle -A FORWARD -o %i -i ${NET_IFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
EOF
        # Replace ${NET_IFACE} in the appended section
        sed -i "s/\${NET_IFACE}/${NET_IFACE}/g" "$WGDIR/wg0.conf"
    else
        cat >> "$WGDIR/wg0.conf" << 'EOF'

# NOTE: MSS clamping disabled (kernel modules not available)
# Streaming performance may be reduced for forwarded traffic
EOF
    fi

    # Add common forwarding rules
    cat >> "$WGDIR/wg0.conf" << EOF

# Enable IP forwarding and NAT for VPN traffic
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${NET_IFACE} -j MASQUERADE
EOF

    # Add PostDown rules (with MSS if available)
    if [ "$MSS_AVAILABLE" = "true" ]; then
        cat >> "$WGDIR/wg0.conf" << 'EOF'
PostDown = iptables -t mangle -D FORWARD -i %i -o ${NET_IFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -t mangle -D FORWARD -o %i -i ${NET_IFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
EOF
        sed -i "s/\${NET_IFACE}/${NET_IFACE}/g" "$WGDIR/wg0.conf"
    fi

    cat >> "$WGDIR/wg0.conf" << EOF
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${NET_IFACE} -j MASQUERADE

# NOTE: Peer configuration is added dynamically at service start
# This allows client keys to be replaced without reconfiguration
# PostUp command below reads client_public.key and adds peer

# Add client peer dynamically from key file
PostUp = wg set %i peer \$(cat ${WGDIR}/client_public.key) allowed-ips 10.99.99.2/32

# Add additional [Peer] sections below for more clients with different IPs:
# [Peer]
# PublicKey = <additional_client_public_key>
# AllowedIPs = 10.99.99.3/32
EOF

    chmod 600 "$WGDIR/wg0.conf"
    success "Server config created: $WGDIR/wg0.conf"
}

create_client_config() {
    info "Creating client configuration..."

    # Check if client_phone.conf already exists (upgrade scenario)
    if [ -f "$WGDIR/client_phone.conf" ]; then
        warning "client_phone.conf already exists - preserving existing configuration"
        info "If you need to regenerate, delete $WGDIR/client_phone.conf and reinstall"
        return 0
    fi

    cat > "$WGDIR/client_phone.conf" << EOF
[Interface]
# WireGuard VPN Client Configuration for Phone/Mobile
# Generated by TNAP WireGuard Installer v${VERSION}
# Import this file to WireGuard app on your phone
# Server: $(hostname) (${LOCAL_IP})

PrivateKey = ${CLIENT_PRIVATE}
Address = 10.99.99.2/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
# TNAP/Enigma2 Receiver VPN Server
PublicKey = ${SERVER_PUBLIC}
Endpoint = ${PUBLIC_IP}:51820
AllowedIPs = 10.99.99.0/24, 192.168.0.0/16
PersistentKeepalive = 25

# AllowedIPs explanation:
# 10.99.99.0/24 - VPN network (access VPN server at 10.99.99.1)
# 192.168.0.0/16 - Access to home network devices (adjust to match your network)
# Change to 0.0.0.0/0 to route ALL internet traffic through VPN (full tunnel)
EOF

    chmod 600 "$WGDIR/client_phone.conf"
    success "Client config created: $WGDIR/client_phone.conf"
}

enable_ip_forwarding() {
    info "Enabling IP forwarding..."

    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Make it permanent
    if grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null; then
        sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    else
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    success "IP forwarding enabled"
}

configure_firewall() {
    info "Configuring firewall..."

    if [ -f /etc/init.d/firewall ]; then
        # TNAP firewall plugin detected
        info "TNAP firewall plugin found"

        # Load xt-tcpudp module if available
        modprobe xt_tcpudp 2>/dev/null || true

        # Restart firewall to apply WireGuard rules
        /etc/init.d/firewall restart >/dev/null 2>&1 && \
            success "TNAP firewall restarted with WireGuard rules" || \
            warning "Could not restart TNAP firewall"

        # Verify rules
        if iptables -L INPUT -n | grep -q 51820; then
            success "Firewall rule for UDP 51820 verified"
        else
            warning "Firewall rule for UDP 51820 not found (may need manual configuration)"
        fi
    else
        # No TNAP firewall - add basic iptables rule
        info "No TNAP firewall detected, adding basic iptables rule..."

        # Check if iptables rule already exists
        if ! iptables -L INPUT -n | grep -q 51820; then
            # Try to add rule (may fail on some systems)
            if iptables -I INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null; then
                success "Basic firewall rule added for UDP 51820"
            else
                warning "Could not add iptables rule automatically"
                info "Manually add rule: iptables -I INPUT -p udp --dport 51820 -j ACCEPT"
                info "Or configure your image's firewall to allow UDP 51820"
            fi
        else
            success "Firewall rule for UDP 51820 already exists"
        fi
    fi
}

create_init_script() {
    info "Creating init script for auto-start on boot..."

    cat > /etc/init.d/wireguard << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          wireguard
# Required-Start:    $network $local_fs
# Required-Stop:     $network $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: WireGuard VPN
# Description:       WireGuard VPN server for self-hosted VPN
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

case "$1" in
    start)
        echo "Starting WireGuard VPN..."
        /usr/bin/wg-quick up wg0
        ;;
    stop)
        echo "Stopping WireGuard VPN..."
        /usr/bin/wg-quick down wg0
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        /usr/bin/wg show wg0
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit 0
EOF

    chmod +x /etc/init.d/wireguard

    # Enable auto-start (works on most Enigma2 images)
    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d wireguard defaults >/dev/null 2>&1
        success "Init script created and enabled (update-rc.d)"
    else
        # Fallback: create symlinks manually
        ln -sf /etc/init.d/wireguard /etc/rc2.d/S99wireguard 2>/dev/null
        ln -sf /etc/init.d/wireguard /etc/rc3.d/S99wireguard 2>/dev/null
        ln -sf /etc/init.d/wireguard /etc/rc4.d/S99wireguard 2>/dev/null
        ln -sf /etc/init.d/wireguard /etc/rc5.d/S99wireguard 2>/dev/null
        ln -sf /etc/init.d/wireguard /etc/rc0.d/K01wireguard 2>/dev/null
        ln -sf /etc/init.d/wireguard /etc/rc1.d/K01wireguard 2>/dev/null
        ln -sf /etc/init.d/wireguard /etc/rc6.d/K01wireguard 2>/dev/null
        success "Init script created and enabled (manual symlinks)"
    fi
}

start_wireguard() {
    info "Starting WireGuard VPN server..."

    # Stop if already running
    wg-quick down wg0 2>/dev/null || true

    # Start WireGuard
    if wg-quick up wg0; then
        success "WireGuard VPN server started"
    else
        error "Failed to start WireGuard VPN server"
    fi

    # Verify
    sleep 1
    if wg show wg0 >/dev/null 2>&1; then
        success "WireGuard interface wg0 is up"
    else
        error "WireGuard interface wg0 is not running"
    fi
}

# Note: /etc/autoinstall is a PACKAGE LIST for AutoBackup, not a shell script
# Do not add shell code to /etc/autoinstall - it will break package restoration
# Post-restore activation needs to use a different mechanism

show_configuration_summary() {
    echo ""
    echo "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo "${GREEN}     WireGuard VPN Installation Complete!${NC}"
    echo "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "${BLUE}Server Information:${NC}"
    echo "  Local IP:     $LOCAL_IP"
    echo "  Public IP:    $PUBLIC_IP"
    echo "  VPN IP:       10.99.99.1"
    echo "  Listen Port:  51820 (UDP)"
    echo ""
    echo "${BLUE}Server Keys:${NC}"
    echo "  Public:  $SERVER_PUBLIC"
    echo "  Private: (stored in $WGDIR/server_private.key)"
    echo ""
    echo "${BLUE}Client Configuration:${NC}"
    echo "  Location: $WGDIR/client_phone.conf"
    echo "  VPN IP:   10.99.99.2"
    echo ""
    echo "${YELLOW}Next Steps:${NC}"
    echo "  1. ${BLUE}Configure Router Port Forwarding:${NC}"
    echo "     - Protocol: UDP"
    echo "     - External Port: 51820"
    echo "     - Internal IP: $LOCAL_IP"
    echo "     - Internal Port: 51820"
    echo ""
    echo "  2. ${BLUE}Setup Phone/Mobile Client:${NC}"
    echo "     - Copy $WGDIR/client_phone.conf to your phone"
    echo "     - Install WireGuard app from App Store/Play Store"
    echo "     - Import the config file"
    echo "     - Connect (must be on mobile data, NOT home WiFi)"
    echo ""
    echo "  3. ${BLUE}Test Connection:${NC}"
    echo "     - Connect from phone"
    echo "     - On receiver, run: wg show"
    echo "     - Look for 'latest handshake' timestamp"
    echo ""
    echo "${BLUE}Configuration Files:${NC}"
    echo "  Server config: $WGDIR/wg0.conf"
    echo "  Client config: $WGDIR/client_phone.conf"
    echo "  Log file:      $LOGFILE"
    echo ""
    echo "${BLUE}Useful Commands:${NC}"
    echo "  Check status:    wg show"
    echo "  Stop VPN:        /etc/init.d/wireguard stop"
    echo "  Start VPN:       /etc/init.d/wireguard start"
    echo "  Restart VPN:     /etc/init.d/wireguard restart"
    echo "  View config:     cat $WGDIR/wg0.conf"
    echo "  Check firewall:  iptables -L INPUT -n | grep 51820"
    echo ""
    echo "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "${GREEN}✓ WireGuard will start automatically on boot${NC}"
    echo "${GREEN}✓ Installation completed successfully!${NC}"
    echo ""
    echo "${GREEN}✓ Auto-Backup Support:${NC}"
    echo "  Your WireGuard configuration will be automatically backed up"
    echo "  during image upgrades if you have AutoBackup enabled in TNAP."
    echo "  Keys and configs will be restored after flashing new images."
    echo ""
    echo "${YELLOW}IMPORTANT:${NC} If you need to use commercial VPN services"
    echo "(Surfshark, NordVPN, etc.), stop this server first with:"
    echo "/etc/init.d/wireguard stop"
    echo ""
    echo "${BLUE}For support and documentation: https://tnapimages.com${NC}"
    echo ""
}

# Main execution
main() {
    banner
    log "=== WireGuard VPN Installation Started ==="

    # CRITICAL: Check for conflicting Firewall plugin
    if [ -f /etc/init.d/firewall ] && /etc/init.d/firewall status 2>/dev/null | grep -q "policy DROP"; then
        echo ""
        echo "================================================================"
        error "TNAP Firewall plugin detected and active!"
        echo ""
        echo "================================================================"
        echo "CONFLICT: Cannot install WireGuard alongside Firewall plugin"
        echo "================================================================"
        echo ""
        echo "These plugins have INCOMPATIBLE security models:"
        echo ""
        echo "  Firewall Plugin: Selective internet access (whitelist-based)"
        echo "  WireGuard Plugin: VPN-only access (internet blocked)"
        echo ""
        echo "Installing both causes connection issues and security conflicts!"
        echo ""
        echo "Choose ONE approach:"
        echo ""
        echo "  KEEP FIREWALL: Cancel this WireGuard installation"
        echo ""
        echo "  KEEP WIREGUARD: Remove Firewall plugin first:"
        echo "    - Menu > Plugins > Remove Firewall Plugin"
        echo "    OR: opkg remove enigma2-plugin-security-firewall"
        echo "    Then re-run this WireGuard installer"
        echo ""
        echo "================================================================"
        echo "Installation ABORTED to prevent conflicts"
        echo "================================================================"
        exit 1
    fi

    check_requirements
    check_internet
    install_wireguard_packages
    install_optional_dependencies
    generate_keys
    get_network_info
    create_server_config
    create_client_config
    enable_ip_forwarding
    configure_firewall
    create_init_script
    start_wireguard
    show_configuration_summary

    # Note: Post-restore WireGuard activation handled by AutoBackup
    # The /etc/wireguard/ directory and /etc/init.d/wireguard are backed up automatically
    # Post-restore script in /usr/script/wireguard-post-restore.sh activates WireGuard
    # WireGuard will auto-start on boot via /etc/init.d/wireguard

    log "=== WireGuard VPN Installation Completed Successfully ==="
    success "Installation complete! Check $LOGFILE for details."
}

# Run main function
main "$@"
