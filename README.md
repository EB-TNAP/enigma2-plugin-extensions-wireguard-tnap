# WireGuard TNAP Server

A self-hosted WireGuard VPN server plugin for Enigma2 satellite receivers. It turns a TNAP/OpenPLi receiver into a secure VPN gateway, giving you encrypted remote access to the receiver and your home network from anywhere.

**Version 2.1** — menu-driven interface, redesigned full-size screens, and a new Kernel Module Blacklist Manager.

---

## ⚠️ Important: Mutual Exclusivity

**This plugin cannot be installed alongside the Firewall Security plugin or commercial WireGuard client plugins.**

Both this plugin and the Firewall Security plugin manage iptables rules, but with incompatible security models:

| | WireGuard TNAP Server | Firewall Security Plugin |
|---|---|---|
| Access model | VPN-only (internet exposure blocked) | Selective, whitelist-based |
| Best for | Remote access via encrypted tunnel | Internet-facing receivers |
| Monitoring | `wg show` handshake status | Attack logging |

Installing both simultaneously causes connection failures and conflicting rules. **Choose one.** If in doubt, choose WireGuard — it is simpler and exposes nothing to the open internet.

---

## Features

- **One-press installation** — automated server setup, key generation, firewall configuration, and boot auto-start
- **Menu-driven GUI** — full-size, skin-adaptive screens with standard color-button navigation and per-item help text
- **Live status view** — interface state, peer handshakes, firewall rule check, and active configuration in one screen
- **Kernel Module Blacklist Manager** — blacklist or re-enable kernel modules from the GUI (see below)
- **Backup/restore aware** — configuration and keys survive reflashes via TNAP AutoBackup, with automatic post-restore activation
- **Key-preserving reinstall** — re-run setup without breaking existing clients
- **Universal compatibility** — works on all TNAP/OpenPLi-supported receivers

## What is WireGuard?

WireGuard is a modern, high-performance VPN protocol. It runs in kernel space for maximum throughput, uses state-of-the-art cryptography (Curve25519, ChaCha20, Poly1305), and has a minimal attack surface — under 4,000 lines of code. It consistently outperforms OpenVPN and IPsec, which matters on receiver-class CPUs.

## Use Cases

- **Remote access** — reach your receiver's web interface, streams, and home network from anywhere
- **Secure streaming** — watch your satellite TV remotely over an encrypted tunnel
- **IoT gateway** — secure path to home automation devices
- **Public WiFi privacy** — route your phone's traffic through your home connection

---

## Installation

### Via the TNAP/OpenPLi feed

```sh
opkg update
opkg install enigma2-plugin-extensions-wireguard-tnap
```

### Manual installation

1. Download the `.ipk` package from the releases page
2. Transfer it to the receiver via SCP/FTP
3. Install:

```sh
opkg install enigma2-plugin-extensions-wireguard-tnap_*.ipk
```

## Quick Start

1. Open **Menu → Plugins → WireGuard TNAP Server**
2. Select **Install WireGuard server** and confirm — installation takes 2–3 minutes
3. Forward **UDP port 51820** on your router to the receiver's LAN IP
4. Copy `/etc/wireguard/client_phone.conf` to your phone (SCP/FTP)
5. Install the official WireGuard app, import the config, and connect
6. Verify from the receiver: **View server status** should show a recent handshake

> **Testing tip:** test from mobile data, not your home WiFi — connecting to your own public IP from inside the LAN fails on many routers (NAT hairpinning).

---

## Kernel Module Blacklist Manager

New in v2.0. Accessible from the main menu or the **BLUE** button.

### Why it exists

Some receivers — notably the **Octagon SF8008** with its limited flash and RAM — ship kernels that auto-load out-of-tree USB WiFi drivers such as `88x2cu` and `8192eu` even when no matching adapter is present or wanted. These drivers waste memory and can conflict with other network drivers. The traditional fix is a hand-made modprobe file:

```sh
cat > /etc/modprobe.d/blacklist-usb-wifi.conf <<'EOF'
blacklist 88x2cu
blacklist 8192eu
EOF
```

The Blacklist Manager does this from the remote control — no shell required.

### Why blacklisted modules can come back after a reboot

A modprobe.d `blacklist` entry only affects **alias-based auto-loading** (udev running `modprobe -b`). It is completely ignored by:

- explicit loads by name — `modprobe 88x2cu` in a vendor/boot script, or an entry in `/etc/modules` or `/etc/modules-load.d/*.conf`
- direct `insmod /lib/modules/.../88x2cu.ko` calls in init scripts

That's why a plain blacklist file can appear to work (`modprobe -r` unloads the module) yet the module is loaded again on the next boot. The manager therefore applies a **layered defense** when you blacklist a module:

1. `blacklist <mod>` — blocks alias auto-loading (udev/hotplug)
2. `install <mod> /bin/true` — makes explicit `modprobe <mod>` a no-op
3. The module is removed from `/etc/modules` and `/etc/modules-load.d/` if present
4. A late-boot safety net, `/etc/init.d/tnap-module-blacklist` (S99), runs after all vendor scripts and unloads any blacklisted module that still got loaded — this catches the `insmod` case, which nothing in modprobe.d can block

The safety-net script parses *all* blacklist lines in `/etc/modprobe.d/*.conf`, so it also protects entries in hand-made files. It is installed automatically when the first entry is added and removed when the last entry goes. Opening the manager also upgrades entries created before v2.1 (adds the missing `install` lines and the S99 script).

Neither blacklisting nor unloading deletes the `.ko` from flash — that requires removing the package, e.g. `opkg remove kernel-module-88x2cu`.

### Immediate unload

Blacklisting a currently loaded module offers to unload it on the spot, and the **BLUE** button unloads *all* loaded blacklisted modules in one pass — equivalent to:

```sh
modprobe -r 88x2cu 8192eu
```

`modprobe -r` is used rather than `rmmod` because it also unloads dependency modules that are no longer needed. If a module refuses to unload (in use, or built into the kernel), it stays blacklisted and the S99 safety net removes it on the next boot.

### How it works

- The manager scans **all** `/etc/modprobe.d/*.conf` files, so entries you created by hand (e.g. `blacklist-usb-wifi.conf`) are detected and shown with their source file
- New blacklist entries are written to the plugin-managed file `/etc/modprobe.d/blacklist-tnap.conf`
- Removing an entry edits it out of whichever file contains it, including hand-made files
- Each entry shows its blacklist state and whether the module is **currently loaded**
- **GREEN/OK** toggles the blacklist for the selected module; **BLUE** unloads all loaded blacklisted modules now (`modprobe -r`); **MENU** offers a reboot

### Presets and custom modules

Common out-of-tree USB WiFi drivers are offered as one-press presets (`88x2cu`, `8192eu`, `8188eu`, `8821au`, `rtl8xxxu`, `mt7601u`). Any other module can be added by name with the **YELLOW** button. Attempting to blacklist a known-critical module (e.g. `wireguard`, `dvb_core`, USB host drivers) triggers an explicit warning first.

### Safety notes

- Blacklisting only prevents **automatic** loading; `modprobe <name>` still works manually
- If you blacklist a module your receiver actually needs (tuner, USB, network), remove the entry via the manager or delete the line from `/etc/modprobe.d/blacklist-tnap.conf` over SSH — the files are plain text and can always be repaired from a shell
- Blacklisting and unloading free **RAM**, not flash. On space-limited receivers like the SF8008, reclaim flash by also removing the driver package: `opkg remove kernel-module-88x2cu kernel-module-8192eu` (the blacklist entry then guards against the driver returning with a future image or feed update)

---

## Configuration

### Server configuration

The installer generates `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.99.99.1/24
ListenPort = 51820
PrivateKey = <auto-generated>

[Peer]
# Phone client
PublicKey = <client-public-key>
AllowedIPs = 10.99.99.2/32
```

To add more clients, generate a key pair and append a `[Peer]` section with the next free VPN IP (`10.99.99.3/32`, etc.), then restart:

```sh
wg genkey | tee client2_private.key | wg pubkey > client2_public.key
/etc/init.d/wireguard restart
```

### Client configuration

The installer creates a ready-to-import phone config at `/etc/wireguard/client_phone.conf`:

```ini
[Interface]
Address = 10.99.99.2/24
PrivateKey = <client-private-key>
DNS = 8.8.8.8

[Peer]
PublicKey = <server-public-key>
Endpoint = <your-public-ip>:51820
AllowedIPs = 10.99.99.0/24, 192.168.1.0/24
PersistentKeepalive = 25
```

Replace `<your-public-ip>` with your public IP or DDNS hostname. Adjust the second `AllowedIPs` subnet to match your actual LAN.

### Dynamic DNS

If your ISP assigns dynamic IPs, use a DDNS provider (DuckDNS, No-IP, Dynu) and put the hostname in the client's `Endpoint` instead of an IP.

---

## Backup and Restore

With TNAP AutoBackup enabled, the following are preserved across reflashes:

- Server configuration and all keys (`/etc/wireguard/`)
- Init script (`/etc/init.d/wireguard`)
- Client configurations

After restoring a backup on a fresh image, the post-restore script (`/usr/script/wireguard-post-restore.sh`, executed by AutoBackup) re-enables IP forwarding, reloads the kernel module, and restarts the service automatically. Existing clients reconnect without any reconfiguration.

For development/testing, `wireguard-backup-helper.sh` copies a freshly built IPK into backup folders so AutoBackup auto-installs it after a flash.

---

## Uninstallation

**Via GUI:** main menu → **Uninstall server** → confirm.

**Via shell:**

```sh
/usr/lib/enigma2/python/Plugins/Extensions/WireGuardTNAP/wireguard-uninstall.sh
```

The uninstaller stops the service, removes configs and keys, deletes firewall rules and auto-start, and removes the packages. A temporary copy of your keys is placed in `/tmp/wireguard-backup-<timestamp>` — copy it to USB/HDD before rebooting if you want to keep it. Uninstalling is required before installing commercial WireGuard client plugins.

---

## Troubleshooting

### Cannot connect to VPN

1. Verify the server is running: `wg show`
2. Confirm router port forwarding (UDP 51820 → receiver LAN IP)
3. Verify the public IP/DDNS hostname in the client config
4. Check the firewall rule: `iptables -L INPUT -n | grep 51820`
5. Test from mobile data, not home WiFi

### Server not starting

```sh
dmesg | grep wireguard
logread | grep wireguard
```

Common causes: kernel module not loaded (`modprobe wireguard`), port in use (change `ListenPort`), wrong permissions (`chmod 600 /etc/wireguard/wg0.conf`).

### Poor performance / frequent drops

- Keep the default MTU (1420) unless you have a specific reason to change it
- Ensure `PersistentKeepalive = 25` is set in the client config (maintains NAT mappings)
- Try a different `ListenPort` if your ISP throttles common VPN ports

### Handshake works but no LAN access

Verify IP forwarding is on (`cat /proc/sys/net/ipv4/ip_forward` should print `1`) and that the client's `AllowedIPs` includes your LAN subnet.

---

## Requirements

- Enigma2 receiver running a TNAP or OpenPLi image
- Linux kernel 3.10+ (5.6+ has WireGuard built in)
- Internet connection and router port-forwarding capability
- ~10 MB free storage

Tested on: Octagon SF8008, Edision osmio4k, and all TNAP/OpenPLi-supported receivers with kernel 4.x+.

## Security

- Modern cryptography only: Curve25519 key exchange, ChaCha20 encryption, Poly1305 authentication
- Public-key authentication — no passwords to leak or brute-force
- Private keys are generated on-device and stored with `600` permissions
- Silent to port scans: WireGuard does not respond to unauthenticated packets
- Minimal attack surface compared to traditional VPN daemons

## Roadmap

- **Commercial VPN client support** — connect the receiver as a client to services such as Surfshark, NordVPN, Mullvad, and others by importing their WireGuard configs, alongside (or instead of) the self-hosted server
- **On-screen QR code** for client configuration import
- **Multi-client management** — add/remove peers from the GUI

## License

GNU General Public License v2.0 — Copyright (C) 2025–2026 TNAP Development Team

## Credits

- **Development:** TNAP Team
- **Testing:** Community contributors
- **WireGuard:** Jason A. Donenfeld and contributors

## Links & Support

- GitHub: https://github.com/EB-TNAP/enigma2-plugin-extensions-wireguard-tnap
- Issue tracker: https://github.com/EB-TNAP/enigma2-plugin-extensions-wireguard-tnap/issues
- TNAP: https://tnapimages.com | Forum: https://legitfta.com
- WireGuard: https://www.wireguard.com/

When reporting issues, please include: receiver model, image version, error messages/logs (`/tmp/wireguard-install.log`), and steps to reproduce.
