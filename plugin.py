# -*- coding: utf-8 -*-
"""
WireGuard TNAP Server Plugin
Self-hosted VPN server for TNAP/OpenPLi receivers

Version: 2.1
Date: 2026-07-16

Compatible with all receivers: SF8008, Edision osmio4k, and all TNAP-supported hardware
Skin-adaptive design: Works with any Enigma2 skin (BlueBD, Transparency, AtileHD, etc.)

v2.1 changes:
  - Blacklist hardening: modprobe.d 'blacklist' alone only affects alias
    auto-loading and is ignored by explicit 'modprobe <name>' calls,
    /etc/modules(-load.d) entries and direct insmod in vendor scripts -
    which is why modules reappeared after reboot. Now, blacklisting a
    module also:
      * writes 'install <mod> /bin/true' (defeats modprobe-by-name)
      * removes the module from /etc/modules and /etc/modules-load.d/
      * installs a late-boot S99 init script that modprobe -r's any
        blacklisted module that still got loaded (defeats insmod)

v2.0 changes:
  - Menu-driven main screen (scales cleanly as features are added)
  - Larger, professional screen layouts with standard color-button bars
  - New: Kernel Module Blacklist Manager (manage /etc/modprobe.d entries,
    e.g. blacklist out-of-tree USB WiFi drivers 88x2cu / 8192eu on SF8008,
    and unload loaded modules immediately via 'modprobe -r mod1 mod2 ...')
"""

from Screens.Screen import Screen
from Screens.MessageBox import MessageBox
from Screens.VirtualKeyBoard import VirtualKeyBoard
from Components.ActionMap import ActionMap
from Components.Label import Label
from Components.MenuList import MenuList
from Components.ScrollLabel import ScrollLabel
from Components.Console import Console
from Plugins.Plugin import PluginDescriptor
from Tools.Directories import fileExists
import os
import re
import glob

PLUGIN_VERSION = "2.1"
PLUGIN_DIR = "/usr/lib/enigma2/python/Plugins/Extensions/WireGuardTNAP"

# Late-boot safety net: unloads blacklisted modules that were loaded by
# mechanisms that ignore modprobe.d (explicit modprobe by name, insmod in
# vendor scripts, /etc/modules entries restored by other tools).
UNLOAD_INIT_SCRIPT = "/etc/init.d/tnap-module-blacklist"
UNLOAD_SCRIPT_NAME = "tnap-module-blacklist"

UNLOAD_SCRIPT_BODY = """#!/bin/sh
### BEGIN INIT INFO
# Provides:          tnap-module-blacklist
# Required-Start:    $local_fs
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: Unload blacklisted kernel modules
# Description:       Managed by the WireGuard TNAP Server plugin.
#                    modprobe.d blacklists only affect alias auto-loading;
#                    explicit modprobe-by-name and insmod in vendor/boot
#                    scripts ignore them. This runs late in boot and unloads
#                    any blacklisted module that slipped through.
### END INIT INFO

case "$1" in
    start|restart|reload|force-reload)
        MODS=$(sed -n 's/^[[:space:]]*blacklist[[:space:]][[:space:]]*\\([^[:space:]]*\\).*/\\1/p' /etc/modprobe.d/*.conf 2>/dev/null | sort -u)
        for mod in $MODS; do
            m=$(echo "$mod" | tr '-' '_')
            if grep -q "^$m " /proc/modules 2>/dev/null; then
                modprobe -r "$mod" 2>/dev/null || rmmod "$m" 2>/dev/null || true
            fi
        done
        ;;
    stop|status)
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        ;;
esac
exit 0
"""

# File owned/managed by this plugin for user blacklist entries.
# Entries found in OTHER /etc/modprobe.d/*.conf files (e.g. a hand-made
# blacklist-usb-wifi.conf) are detected and can be removed as well.
BLACKLIST_FILE = "/etc/modprobe.d/blacklist-tnap.conf"
BLACKLIST_HEADER = "# Managed by WireGuard TNAP Server plugin - kernel module blacklist\n"

# Common out-of-tree / problem modules offered as one-press presets.
# Useful on space-limited receivers such as the Octagon SF8008 where
# unused USB WiFi drivers waste RAM and can destabilize the box.
PRESET_MODULES = [
    ("88x2cu",   "Realtek RTL8812CU/8822CU USB WiFi"),
    ("8192eu",   "Realtek RTL8192EU USB WiFi"),
    ("8188eu",   "Realtek RTL8188EU USB WiFi"),
    ("8821au",   "Realtek RTL8811AU/8821AU USB WiFi"),
    ("rtl8xxxu", "Realtek generic USB WiFi (in-kernel)"),
    ("mt7601u",  "MediaTek MT7601U USB WiFi"),
]

# Modules the receiver genuinely needs - warn loudly before blacklisting.
CRITICAL_MODULES = ("wireguard", "dvb_core", "dvbcore", "ext4",
                    "usbcore", "ehci_hcd", "xhci_hcd")


# ---------------------------------------------------------------------------
# Blacklist helpers
# ---------------------------------------------------------------------------

def readBlacklistEntries():
    """Scan all /etc/modprobe.d/*.conf files.
    Returns dict: module_name -> file path containing its blacklist line."""
    entries = {}
    for path in sorted(glob.glob("/etc/modprobe.d/*.conf")):
        try:
            with open(path, "r") as f:
                for line in f:
                    m = re.match(r"^\s*blacklist\s+(\S+)", line)
                    if m:
                        entries[m.group(1)] = path
        except (IOError, OSError):
            pass
    return entries


def addBlacklistEntry(module):
    """Append blacklist + install lines to the plugin-managed file.

    'blacklist <mod>'          - blocks alias-based auto-loading (udev)
    'install <mod> /bin/true'  - blocks explicit 'modprobe <mod>' by name,
                                 which ignores plain blacklist entries
    """
    try:
        newfile = not fileExists(BLACKLIST_FILE)
        with open(BLACKLIST_FILE, "a") as f:
            if newfile:
                f.write(BLACKLIST_HEADER)
            f.write("blacklist %s\n" % module)
            f.write("install %s /bin/true\n" % module)
        return True
    except (IOError, OSError):
        return False


def removeBlacklistEntry(module, path):
    """Remove blacklist and 'install <mod> /bin/true' lines for 'module'
    from 'path'. Deletes the plugin-managed file if it becomes empty."""
    try:
        with open(path, "r") as f:
            lines = f.readlines()
        pat = re.compile(r"^\s*(blacklist\s+%s|install\s+%s\s+/bin/true)\s*$" %
                         (re.escape(module), re.escape(module)))
        kept = [l for l in lines if not pat.match(l)]
        remaining = [l for l in kept if l.strip() and not l.strip().startswith("#")]
        if path == BLACKLIST_FILE and not remaining:
            os.remove(path)
        else:
            with open(path, "w") as f:
                f.writelines(kept)
        return True
    except (IOError, OSError):
        return False


def removeFromModulesLoad(module):
    """Remove explicit load entries for 'module' from /etc/modules and
    /etc/modules-load.d/*.conf. These mechanisms load modules BY NAME at
    boot and completely ignore modprobe.d blacklists - a common reason
    blacklisted modules reappear after a reboot.
    Returns the list of files that were modified."""
    changed = []
    variants = {module, module.replace("-", "_"), module.replace("_", "-")}
    paths = ["/etc/modules"] + glob.glob("/etc/modules-load.d/*.conf")
    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r") as f:
                lines = f.readlines()
            kept = [l for l in lines if l.strip() not in variants]
            if len(kept) != len(lines):
                with open(path, "w") as f:
                    f.writelines(kept)
                changed.append(path)
        except (IOError, OSError):
            pass
    return changed


def updateUnloadInitScript():
    """Install (or remove) the late-boot safety-net init script.

    Vendor boot scripts sometimes load drivers with plain 'modprobe <name>'
    or direct 'insmod .../<mod>.ko' - both bypass modprobe.d entirely. The
    S99 script runs after them and unloads any blacklisted module that
    still got loaded. Removed automatically when no blacklist entries
    remain anywhere in /etc/modprobe.d."""
    if readBlacklistEntries():
        try:
            with open(UNLOAD_INIT_SCRIPT, "w") as f:
                f.write(UNLOAD_SCRIPT_BODY)
            os.chmod(UNLOAD_INIT_SCRIPT, 0o755)
        except (IOError, OSError):
            return False
        if os.system("command -v update-rc.d >/dev/null 2>&1") == 0:
            os.system("update-rc.d %s defaults 99 >/dev/null 2>&1" % UNLOAD_SCRIPT_NAME)
        else:
            for lvl in "2345":
                link = "/etc/rc%s.d/S99%s" % (lvl, UNLOAD_SCRIPT_NAME)
                try:
                    if not os.path.lexists(link):
                        os.symlink(UNLOAD_INIT_SCRIPT, link)
                except OSError:
                    pass
        return True
    else:
        os.system("update-rc.d -f %s remove >/dev/null 2>&1" % UNLOAD_SCRIPT_NAME)
        for lvl in "0123456":
            for prefix in ("S99", "K01"):
                try:
                    os.remove("/etc/rc%s.d/%s%s" % (lvl, prefix, UNLOAD_SCRIPT_NAME))
                except OSError:
                    pass
        try:
            os.remove(UNLOAD_INIT_SCRIPT)
        except OSError:
            pass
        return True


def loadedModules():
    """Return set of currently loaded kernel module names (from /proc/modules)."""
    mods = set()
    try:
        with open("/proc/modules", "r") as f:
            for line in f:
                mods.add(line.split()[0])
    except (IOError, OSError):
        pass
    return mods


def normalizeModName(name):
    # lsmod reports underscores; modprobe accepts either
    return name.replace("-", "_")


# ---------------------------------------------------------------------------
# Main menu screen
# ---------------------------------------------------------------------------

class WireGuardMain(Screen):
    """Menu-driven main screen with live item descriptions."""

    skin = """
        <screen name="WireGuardMain" position="center,center" size="980,640" title="WireGuard TNAP Server">
            <widget name="status" position="20,15" size="940,40" font="Regular;28" halign="center" valign="center" foregroundColor="#00a0f0a0" />
            <eLabel position="20,62" size="940,2" backgroundColor="#00555555" />
            <widget name="menu" position="30,80" size="440,420" font="Regular;26" itemHeight="42" scrollbarMode="showOnDemand" />
            <eLabel position="490,80" size="2,420" backgroundColor="#00555555" />
            <widget name="description" position="510,80" size="450,420" font="Regular;22" foregroundColor="#00bbbbbb" />
            <widget name="hint" position="20,515" size="940,60" font="Regular;20" halign="center" foregroundColor="#00888888" />
            <eLabel position="20,585" size="940,2" backgroundColor="#00555555" />
            <eLabel position="30,600" size="8,30" backgroundColor="#00ff2525" />
            <widget name="key_red" position="48,600" size="180,30" font="Regular;22" valign="center" />
            <eLabel position="270,600" size="8,30" backgroundColor="#0025ff25" />
            <widget name="key_green" position="288,600" size="180,30" font="Regular;22" valign="center" />
            <eLabel position="510,600" size="8,30" backgroundColor="#00ffff25" />
            <widget name="key_yellow" position="528,600" size="200,30" font="Regular;22" valign="center" />
            <eLabel position="750,600" size="8,30" backgroundColor="#002563ff" />
            <widget name="key_blue" position="768,600" size="190,30" font="Regular;22" valign="center" />
        </screen>
    """

    def __init__(self, session):
        Screen.__init__(self, session)
        self.session = session
        self.setTitle("WireGuard TNAP Server v%s" % PLUGIN_VERSION)

        self["status"] = Label("")
        self["description"] = Label("")
        self["hint"] = Label("Self-hosted WireGuard VPN server for secure remote access "
                             "to your receiver and home network.")
        self["key_red"] = Label("Exit")
        self["key_green"] = Label("Select")
        self["key_yellow"] = Label("Server Status")
        self["key_blue"] = Label("Kernel Modules")

        self["menu"] = MenuList([])

        self["actions"] = ActionMap(["ColorActions", "OkCancelActions", "DirectionActions"], {
            "ok": self.okPressed,
            "green": self.okPressed,
            "red": self.close,
            "cancel": self.close,
            "yellow": self.openStatus,
            "blue": self.openModuleManager,
            "up": self.moveUp,
            "down": self.moveDown,
        }, -1)

        self.menuEntries = []
        self.buildMenu()

    # -- menu construction ---------------------------------------------------

    def isInstalled(self):
        return fileExists("/etc/wireguard/wg0.conf") and fileExists("/etc/init.d/wireguard")

    def buildMenu(self):
        moduleEntry = (
            "Kernel module blacklist manager", "modules",
            "Blacklist or un-blacklist kernel modules via /etc/modprobe.d.\n\n"
            "Useful on space-limited receivers (e.g. Octagon SF8008) to keep "
            "unused USB WiFi drivers such as 88x2cu or 8192eu from loading at boot.")
        aboutEntry = (
            "About / Help", "about",
            "Version information, quick-start steps and support links.")

        if self.isInstalled():
            self["status"].setText("Server status: INSTALLED")
            entries = [
                ("View server status", "status",
                 "Show the live WireGuard interface state (wg show), connected "
                 "peers, handshake times, firewall rule and the active server "
                 "configuration."),
                ("Reinstall server  (keeps existing keys)", "reinstall",
                 "Re-run the installer while preserving your existing keys.\n\n"
                 "Client devices keep working - no reconfiguration needed."),
                moduleEntry,
                ("Uninstall server", "uninstall",
                 "Completely remove WireGuard: keys, configuration, firewall rules "
                 "and auto-start.\n\nRequired before installing commercial "
                 "WireGuard client plugins."),
                aboutEntry,
            ]
        else:
            self["status"].setText("Server status: NOT INSTALLED")
            entries = [
                ("Install WireGuard server", "install",
                 "One-press automated setup:\n\n"
                 "\u2022 Installs wireguard-tools and iptables\n"
                 "\u2022 Generates server and client keys\n"
                 "\u2022 Configures firewall and auto-start\n"
                 "\u2022 Creates a ready-to-import phone client config\n\n"
                 "Takes 2-3 minutes. Requires internet and router port "
                 "forwarding (UDP 51820)."),
                moduleEntry,
                aboutEntry,
            ]
        self.menuEntries = entries
        self["menu"].setList([e[0] for e in entries])
        self.updateDescription()

    def updateDescription(self):
        idx = self["menu"].getSelectionIndex()
        if idx is not None and 0 <= idx < len(self.menuEntries):
            self["description"].setText(self.menuEntries[idx][2])

    def moveUp(self):
        self["menu"].up()
        self.updateDescription()

    def moveDown(self):
        self["menu"].down()
        self.updateDescription()

    # -- actions ---------------------------------------------------------------

    def okPressed(self):
        idx = self["menu"].getSelectionIndex()
        if idx is None or idx >= len(self.menuEntries):
            return
        action = self.menuEntries[idx][1]
        if action == "install":
            self.install()
        elif action == "reinstall":
            self.reinstall()
        elif action == "uninstall":
            self.uninstall()
        elif action == "status":
            self.openStatus()
        elif action == "modules":
            self.openModuleManager()
        elif action == "about":
            self.showAbout()

    def openStatus(self):
        self.session.open(WireGuardStatus)

    def openModuleManager(self):
        self.session.open(KernelModuleManager)

    def showAbout(self):
        text = (
            "WireGuard TNAP Server v%s\n\n"
            "Self-hosted WireGuard VPN server for TNAP/OpenPLi receivers.\n\n"
            "Quick start:\n"
            "1. Install the server from the main menu\n"
            "2. Forward UDP port 51820 on your router to this receiver\n"
            "3. Copy /etc/wireguard/client_phone.conf to your phone\n"
            "4. Import it in the WireGuard app and connect\n\n"
            "Note: cannot be installed alongside the Firewall Security plugin\n"
            "or commercial WireGuard client plugins.\n\n"
            "Support: https://tnapimages.com" % PLUGIN_VERSION
        )
        self.session.open(MessageBox, text, MessageBox.TYPE_INFO)

    def install(self):
        message = (
            "This will install the WireGuard VPN server.\n\n"
            "The installation will:\n"
            "\u2022 Install packages (wireguard-tools, iptables)\n"
            "\u2022 Generate security keys\n"
            "\u2022 Configure the firewall\n"
            "\u2022 Enable auto-start on boot\n\n"
            "Takes 2-3 minutes. Continue?"
        )
        self.session.openWithCallback(self.installConfirmed, MessageBox,
                                      message, MessageBox.TYPE_YESNO, default=True)

    def installConfirmed(self, answer):
        if answer:
            self.session.openWithCallback(self.refreshAfterChild,
                                          WireGuardInstaller, mode="install")

    def reinstall(self):
        message = (
            "Reinstall WireGuard while preserving your keys.\n\n"
            "The VPN will continue working without reconfiguring clients.\n\n"
            "Continue?"
        )
        self.session.openWithCallback(self.reinstallConfirmed, MessageBox,
                                      message, MessageBox.TYPE_YESNO, default=False)

    def reinstallConfirmed(self, answer):
        if answer:
            self.session.openWithCallback(self.refreshAfterChild,
                                          WireGuardInstaller, mode="reinstall")

    def uninstall(self):
        message = (
            "WARNING: This will completely remove WireGuard!\n\n"
            "All keys, configs and firewall rules will be deleted.\n"
            "You will need to reconfigure clients if you reinstall.\n\n"
            "Required before installing commercial WireGuard clients.\n\n"
            "Are you SURE?"
        )
        self.session.openWithCallback(self.uninstallConfirmed, MessageBox,
                                      message, MessageBox.TYPE_YESNO, default=False)

    def uninstallConfirmed(self, answer):
        if answer:
            self.session.openWithCallback(self.refreshAfterChild,
                                          WireGuardInstaller, mode="uninstall")

    def refreshAfterChild(self, *args):
        # Installed state may have changed - rebuild the menu
        self.buildMenu()


# ---------------------------------------------------------------------------
# Status screen
# ---------------------------------------------------------------------------

class WireGuardStatus(Screen):
    """Live server status - large console-style display."""

    skin = """
        <screen name="WireGuardStatus" position="center,center" size="1160,660" title="WireGuard Server Status">
            <widget name="output" position="20,15" size="1120,580" font="Console;20" />
            <eLabel position="20,605" size="1120,2" backgroundColor="#00555555" />
            <eLabel position="30,618" size="8,30" backgroundColor="#00ff2525" />
            <widget name="key_red" position="48,618" size="160,30" font="Regular;22" valign="center" />
            <eLabel position="240,618" size="8,30" backgroundColor="#0025ff25" />
            <widget name="key_green" position="258,618" size="180,30" font="Regular;22" valign="center" />
            <widget name="hint" position="640,618" size="500,30" font="Regular;20" halign="right" valign="center" foregroundColor="#00888888" />
        </screen>
    """

    def __init__(self, session):
        Screen.__init__(self, session)
        self.session = session
        self.console = Console()
        self.setTitle("WireGuard Server Status")

        self["output"] = ScrollLabel("Loading WireGuard status...")
        self["key_red"] = Label("Close")
        self["key_green"] = Label("Refresh")
        self["hint"] = Label("UP/DOWN = scroll")

        self["actions"] = ActionMap(["ColorActions", "OkCancelActions", "DirectionActions"], {
            "red": self.close,
            "cancel": self.close,
            "ok": self.close,
            "green": self.getStatus,
            "up": self["output"].pageUp,
            "down": self["output"].pageDown,
        }, -1)

        self.onLayoutFinish.append(self.getStatus)

    def getStatus(self):
        self["output"].setText("Loading WireGuard status...\n")
        cmd = ("echo '=== Interface (wg show) ==='; wg show 2>&1; "
               "echo; echo '=== Auto-start ==='; "
               "[ -x /etc/init.d/wireguard ] && echo 'Init script: installed' "
               "|| echo 'Init script: MISSING'; "
               "echo; echo '=== Firewall (UDP 51820) ==='; "
               "iptables -L INPUT -n 2>/dev/null | grep 51820 "
               "|| echo 'No explicit rule found'; "
               "echo; echo '=== Server configuration ==='; "
               "cat /etc/wireguard/wg0.conf 2>/dev/null || echo 'No config found'")
        self.console.ePopen(cmd, self.statusCallback)

    def statusCallback(self, result, retval, extra_args=None):
        if isinstance(result, bytes):
            result = result.decode("utf-8", "replace")
        self["output"].setText(result or "Error: could not retrieve WireGuard status")


# ---------------------------------------------------------------------------
# Installer / uninstaller console screen
# ---------------------------------------------------------------------------

class WireGuardInstaller(Screen):
    """Runs the install/uninstall scripts with live console output."""

    skin = """
        <screen name="WireGuardInstaller" position="center,center" size="1160,660" title="WireGuard Installation">
            <widget name="output" position="20,15" size="1120,570" font="Console;20" />
            <eLabel position="20,595" size="1120,2" backgroundColor="#00555555" />
            <widget name="status" position="20,608" size="1120,40" font="Regular;24" halign="center" valign="center" foregroundColor="#00a0f0a0" />
        </screen>
    """

    def __init__(self, session, mode="install"):
        Screen.__init__(self, session)
        self.session = session
        self.console = Console()
        self.mode = mode  # install, reinstall, or uninstall
        self.setTitle("WireGuard %s" %
                      ("Uninstall" if mode == "uninstall" else "Installation"))

        self["output"] = ScrollLabel("")
        self["status"] = Label("Starting...")

        self["actions"] = ActionMap(["OkCancelActions", "DirectionActions"], {
            "ok": self.close,
            "cancel": self.close,
            "up": self["output"].pageUp,
            "down": self["output"].pageDown,
        }, -1)

        self.outputText = ""
        self.onLayoutFinish.append(self.startProcess)

    def startProcess(self):
        if self.mode == "uninstall":
            self["status"].setText("Uninstalling WireGuard... please wait")
            script = os.path.join(PLUGIN_DIR, "wireguard-uninstall.sh")
        else:
            self["status"].setText(
                "%s WireGuard... please wait (2-3 minutes)" %
                ("Reinstalling" if self.mode == "reinstall" else "Installing"))
            script = os.path.join(PLUGIN_DIR, "wireguard-install.sh")

        cmd = "sh %s" % script
        self.appendOutput("Running: %s\n\n" % cmd)
        self.console.ePopen(cmd, self.processCallback)

    def appendOutput(self, text):
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        self.outputText += text
        self["output"].setText(self.outputText)
        self["output"].lastPage()

    def processCallback(self, result, retval, extra_args=None):
        if result:
            self.appendOutput(result)

        if retval == 0:
            if self.mode == "uninstall":
                self["status"].setText("Uninstall complete - press OK to close")
                self.appendOutput("\n\n=== WireGuard Uninstalled ===\n"
                                  "You can now install commercial WireGuard clients.\n")
            else:
                self["status"].setText("Installation complete - press OK to close")
                self.appendOutput("\n\n=== Installation Complete ===\n"
                                  "Next steps:\n"
                                  "1. Router port forwarding (UDP 51820)\n"
                                  "2. Copy /etc/wireguard/client_phone.conf to your phone\n"
                                  "3. Install the WireGuard app and import the config\n")
        else:
            self["status"].setText("ERROR - check output above, press OK to close")
            self.appendOutput("\n\nERROR: process failed with code %s\n"
                              "Log file: /tmp/wireguard-install.log\n" % retval)


# ---------------------------------------------------------------------------
# Kernel module blacklist manager
# ---------------------------------------------------------------------------

class KernelModuleManager(Screen):
    """Manage kernel module blacklisting via /etc/modprobe.d.

    Presets cover common out-of-tree USB WiFi drivers that waste RAM and
    can destabilize space-limited receivers such as the Octagon SF8008.
    Custom module names can be added with the YELLOW button. Entries in
    hand-made files (e.g. blacklist-usb-wifi.conf) are detected too and
    can be removed in place; new entries go to blacklist-tnap.conf.

    NOTE: a modprobe.d blacklist only stops modules from AUTO-LOADING at
    boot. It does not unload running modules and does not delete .ko files
    from flash. BLUE runs 'modprobe -r <mod1> <mod2> ...' to unload all
    loaded blacklisted modules immediately (including their now-unused
    dependencies). To reclaim flash space, remove the corresponding
    kernel-module-* package with opkg.
    """

    skin = """
        <screen name="KernelModuleManager" position="center,center" size="980,640" title="Kernel Module Blacklist Manager">
            <widget name="menu" position="20,15" size="940,420" font="Console;22" itemHeight="38" scrollbarMode="showOnDemand" />
            <eLabel position="20,445" size="940,2" backgroundColor="#00555555" />
            <widget name="info" position="20,455" size="940,120" font="Regular;20" foregroundColor="#00bbbbbb" />
            <eLabel position="20,585" size="940,2" backgroundColor="#00555555" />
            <eLabel position="30,600" size="8,30" backgroundColor="#00ff2525" />
            <widget name="key_red" position="48,600" size="160,30" font="Regular;22" valign="center" />
            <eLabel position="230,600" size="8,30" backgroundColor="#0025ff25" />
            <widget name="key_green" position="248,600" size="220,30" font="Regular;22" valign="center" />
            <eLabel position="490,600" size="8,30" backgroundColor="#00ffff25" />
            <widget name="key_yellow" position="508,600" size="220,30" font="Regular;22" valign="center" />
            <eLabel position="750,600" size="8,30" backgroundColor="#002563ff" />
            <widget name="key_blue" position="768,600" size="190,30" font="Regular;22" valign="center" />
        </screen>
    """

    def __init__(self, session):
        Screen.__init__(self, session)
        self.session = session
        self.setTitle("Kernel Module Blacklist Manager")

        self["menu"] = MenuList([])
        self["info"] = Label(
            "Blacklisting prevents a module from AUTO-LOADING at boot - it does not "
            "unload one that is already running. Use BLUE to unload all loaded "
            "blacklisted modules now (modprobe -r), or press MENU to reboot.\n"
            "On the Octagon SF8008 and similar receivers, blacklisting unused USB "
            "WiFi drivers (88x2cu, 8192eu) frees RAM and avoids driver conflicts.")
        self["key_red"] = Label("Close")
        self["key_green"] = Label("Toggle blacklist")
        self["key_yellow"] = Label("Add custom module")
        self["key_blue"] = Label("Unload blacklisted")

        self["actions"] = ActionMap(["ColorActions", "OkCancelActions",
                                     "DirectionActions", "MenuActions"], {
            "red": self.close,
            "cancel": self.close,
            "ok": self.toggleSelected,
            "green": self.toggleSelected,
            "yellow": self.addCustom,
            "blue": self.unloadAllBlacklisted,
            "menu": self.askReboot,
            "up": self["menu"].up,
            "down": self["menu"].down,
        }, -1)

        self.entries = []
        self.hardenExistingEntries()
        self.buildList()

    def hardenExistingEntries(self):
        """Upgrade entries created before v2.1 (or by hand):
        - ensure the plugin file has 'install <mod> /bin/true' for each of
          its blacklist lines
        - ensure the S99 safety-net init script exists whenever any
          blacklist entries exist (covers hand-made files too, since the
          script parses all of /etc/modprobe.d)"""
        try:
            if fileExists(BLACKLIST_FILE):
                with open(BLACKLIST_FILE, "r") as f:
                    content = f.read()
                missing = [m for m in re.findall(r"^\s*blacklist\s+(\S+)", content, re.M)
                           if not re.search(r"^\s*install\s+%s\s+/bin/true\s*$" %
                                            re.escape(m), content, re.M)]
                if missing:
                    with open(BLACKLIST_FILE, "a") as f:
                        for m in missing:
                            f.write("install %s /bin/true\n" % m)
        except (IOError, OSError):
            pass
        updateUnloadInitScript()

    # -- list construction -----------------------------------------------------

    def buildList(self):
        blacklisted = readBlacklistEntries()          # module -> file
        loaded = loadedModules()

        modules = {}
        for name, desc in PRESET_MODULES:
            modules[name] = desc
        for name in blacklisted:
            modules.setdefault(name, "custom entry")

        self.entries = []
        display = []
        # Blacklisted entries first, then alphabetical
        for name in sorted(modules, key=lambda n: (n not in blacklisted, n)):
            path = blacklisted.get(name)
            is_loaded = normalizeModName(name) in loaded
            state = "[BLACKLISTED]" if path else "[ allowed  ]"
            load = "loaded" if is_loaded else "not loaded"
            external = ""
            if path and path != BLACKLIST_FILE:
                external = "  (%s)" % os.path.basename(path)
            display.append("%s  %-12s %-10s  %s%s" %
                           (state, name, load, modules[name], external))
            self.entries.append((name, path, is_loaded))

        self["menu"].setList(display)

    # -- actions ---------------------------------------------------------------

    def toggleSelected(self):
        idx = self["menu"].getSelectionIndex()
        if idx is None or idx >= len(self.entries):
            return
        name, path, is_loaded = self.entries[idx]

        if path:
            # Currently blacklisted -> remove
            if removeBlacklistEntry(name, path):
                updateUnloadInitScript()  # drops the S99 script if list is now empty
                self.buildList()
                self.session.open(
                    MessageBox,
                    "Removed '%s' from the blacklist (%s).\n\n"
                    "The module can load again after the next reboot, or run:\n"
                    "modprobe %s" % (name, os.path.basename(path), name),
                    MessageBox.TYPE_INFO, timeout=8)
            else:
                self.session.open(MessageBox,
                                  "Could not modify %s" % path,
                                  MessageBox.TYPE_ERROR)
        else:
            # Not blacklisted -> add (warn for critical modules)
            critical = [normalizeModName(c) for c in CRITICAL_MODULES]
            if normalizeModName(name) in critical:
                self.session.openWithCallback(
                    lambda ans, n=name: ans and self.doBlacklist(n),
                    MessageBox,
                    "WARNING: '%s' may be required for normal receiver operation!\n\n"
                    "Blacklisting it could break tuners, USB or the VPN.\n\n"
                    "Blacklist anyway?" % name,
                    MessageBox.TYPE_YESNO, default=False)
            else:
                self.doBlacklist(name)

    def doBlacklist(self, name):
        if not addBlacklistEntry(name):
            self.session.open(MessageBox,
                              "Could not write %s" % BLACKLIST_FILE,
                              MessageBox.TYPE_ERROR)
            return
        cleaned = removeFromModulesLoad(name)
        updateUnloadInitScript()
        is_loaded = normalizeModName(name) in loadedModules()
        self.buildList()

        details = ("Written: blacklist + install /bin/true\n"
                   "Boot safety net (S99 unload script): active")
        if cleaned:
            details += "\nRemoved explicit load entry from: %s" % ", ".join(cleaned)

        if is_loaded:
            self.session.openWithCallback(
                lambda ans, n=name: ans and self.unloadNow(n),
                MessageBox,
                "'%s' is now fully blacklisted for future boots.\n\n%s\n\n"
                "It is still loaded right now. Unload it (modprobe -r)?" %
                (name, details),
                MessageBox.TYPE_YESNO, default=True)
        else:
            self.session.open(
                MessageBox,
                "'%s' is now fully blacklisted.\n\n%s\n\n"
                "It will not load at boot." % (name, details),
                MessageBox.TYPE_INFO, timeout=8)

    def unloadNow(self, name):
        # modprobe -r unloads the module AND any dependency modules that are
        # no longer needed (unlike bare rmmod). Blacklisting alone only stops
        # the module from auto-loading at boot - it never unloads it.
        self.unloadConsole = Console()
        self.unloadConsole.ePopen("modprobe -r %s" % normalizeModName(name),
                                  self.unloadCallback, [name])

    def unloadCallback(self, result, retval, extra_args=None):
        name = extra_args[0] if extra_args else "module"
        self.buildList()
        if retval == 0:
            self.session.open(MessageBox,
                              "'%s' unloaded successfully." % name,
                              MessageBox.TYPE_INFO, timeout=6)
        else:
            self.session.open(
                MessageBox,
                "Could not unload '%s' (in use or built into the kernel).\n\n"
                "It will not load on the next reboot." % name,
                MessageBox.TYPE_WARNING, timeout=8)

    def unloadAllBlacklisted(self):
        """Unload every blacklisted module that is currently loaded, in one
        pass - equivalent to e.g.:  modprobe -r 88x2cu 8192eu"""
        loaded = loadedModules()
        targets = sorted(set(
            normalizeModName(name)
            for name in readBlacklistEntries()
            if normalizeModName(name) in loaded))
        if not targets:
            self.session.open(MessageBox,
                              "No blacklisted modules are currently loaded.\n\n"
                              "Nothing to unload.",
                              MessageBox.TYPE_INFO, timeout=6)
            return
        self.session.openWithCallback(
            lambda ans, t=targets: ans and self.doUnloadAll(t),
            MessageBox,
            "Unload these blacklisted modules now?\n\n"
            "modprobe -r %s" % " ".join(targets),
            MessageBox.TYPE_YESNO, default=True)

    def doUnloadAll(self, targets):
        self.unloadConsole = Console()
        self.unloadConsole.ePopen("modprobe -r %s 2>&1" % " ".join(targets),
                                  self.unloadAllCallback, [targets])

    def unloadAllCallback(self, result, retval, extra_args=None):
        targets = extra_args[0] if extra_args else []
        still = loadedModules()
        remaining = [t for t in targets if t in still]
        self.buildList()
        if isinstance(result, bytes):
            result = result.decode("utf-8", "replace")
        if not remaining:
            self.session.open(MessageBox,
                              "All blacklisted modules unloaded successfully:\n\n%s" %
                              " ".join(targets),
                              MessageBox.TYPE_INFO, timeout=8)
        else:
            self.session.open(
                MessageBox,
                "Could not unload: %s\n(in use or built into the kernel)\n\n"
                "%sThey will not load on the next reboot." %
                (" ".join(remaining), (result.strip() + "\n\n") if result else ""),
                MessageBox.TYPE_WARNING, timeout=10)

    def addCustom(self):
        self.session.openWithCallback(
            self.customEntered, VirtualKeyBoard,
            title="Enter kernel module name to blacklist (e.g. 8188fu)")

    def customEntered(self, name):
        if not name:
            return
        name = name.strip()
        if not re.match(r"^[A-Za-z0-9_\-]+$", name):
            self.session.open(MessageBox,
                              "Invalid module name: %s" % name,
                              MessageBox.TYPE_ERROR)
            return
        if name in readBlacklistEntries():
            self.session.open(MessageBox,
                              "'%s' is already blacklisted." % name,
                              MessageBox.TYPE_INFO, timeout=6)
            return
        self.doBlacklist(name)

    def askReboot(self):
        self.session.openWithCallback(
            self.doReboot, MessageBox,
            "Reboot the receiver now to apply blacklist changes?",
            MessageBox.TYPE_YESNO, default=False)

    def doReboot(self, answer):
        if answer:
            try:
                from Screens.Standby import TryQuitMainloop
                self.session.open(TryQuitMainloop, 2)  # 2 = reboot
            except Exception:
                os.system("reboot")


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def main(session, **kwargs):
    session.open(WireGuardMain)


def Plugins(**kwargs):
    return [
        PluginDescriptor(
            name="WireGuard TNAP Server",
            description="Self-hosted VPN server for secure remote access",
            where=[PluginDescriptor.WHERE_PLUGINMENU, PluginDescriptor.WHERE_EXTENSIONSMENU],
            icon="plugin.png",
            fnc=main
        )
    ]
