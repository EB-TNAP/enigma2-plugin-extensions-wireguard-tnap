# -*- coding: utf-8 -*-
"""
WireGuard TNAP Server Plugin
Self-hosted VPN server for TNAP/OpenPLi receivers

Author: Claude Code (Anthropic AI Assistant)
Model: claude-sonnet-4-5-20250929
Version: 1.0
Date: 2025-11-11

Compatible with all receivers: SF8008, Edision osmio4k, and all TNAP-supported hardware
Skin-adaptive design: Works with any Enigma2 skin (BlueBD, Transparency, AtileHD, etc.)
"""

from Screens.Screen import Screen
from Screens.MessageBox import MessageBox
from Components.ActionMap import ActionMap
from Components.Label import Label
from Components.ScrollLabel import ScrollLabel
from Components.Console import Console
from Plugins.Plugin import PluginDescriptor
from Tools.Directories import fileExists
import os

class WireGuardSetup(Screen):
    """Main setup screen - uses minimal skin for maximum compatibility"""

    # Minimal skin definition - let skin provide layout details
    skin = """
        <screen name="WireGuardSetup" position="center,center" size="560,440" title="WireGuard TNAP Server Setup">
            <widget name="status" position="10,10" size="540,50" font="Regular;22" halign="center" />
            <widget name="info" position="10,70" size="540,320" font="Regular;20" />
            <widget name="actions" position="10,400" size="540,30" font="Regular;18" halign="center" />
        </screen>
    """

    def __init__(self, session):
        Screen.__init__(self, session)
        self.session = session
        self.console = Console()

        # Check if WireGuard is fully installed (not just config files)
        self.wireguard_installed = self.isWireGuardFullyInstalled()

        if self.wireguard_installed:
            status_text = "WireGuard Server: INSTALLED"
            info_text = (
                "WireGuard VPN server is already installed.\n\n"
                "What would you like to do?\n\n"
                "GREEN = View Status\n"
                "YELLOW = Reinstall (keeps keys)\n"
                "RED = Uninstall\n"
                "BLUE = Exit"
            )
        else:
            status_text = "WireGuard Server: NOT INSTALLED"
            info_text = (
                "Welcome to WireGuard TNAP Server!\n\n"
                "Install a self-hosted VPN server on your receiver.\n"
                "Connect securely to your home network from anywhere.\n\n"
                "Compatible with SF8008, osmio4k, and all TNAP receivers.\n"
                "Works with TNAP Auto-Backup (configs preserved).\n\n"
                "Requirements:\n"
                "• Internet connection\n"
                "• Router with port forwarding\n\n"
                "GREEN = Install\n"
                "BLUE = Exit"
            )

        self["status"] = Label(status_text)
        self["info"] = Label(info_text)
        self["actions"] = Label("")

        if self.wireguard_installed:
            self["actions"] = ActionMap(["ColorActions", "OkCancelActions"], {
                "green": self.showStatus,
                "yellow": self.reinstall,
                "red": self.uninstall,
                "blue": self.close,
                "cancel": self.close
            }, -1)
        else:
            self["actions"] = ActionMap(["ColorActions", "OkCancelActions"], {
                "green": self.install,
                "blue": self.close,
                "cancel": self.close
            }, -1)

    def isWireGuardFullyInstalled(self):
        """
        Check if WireGuard is fully installed and operational.
        Not just config files - also init script and proper setup.
        """
        # Check for config file
        if not fileExists("/etc/wireguard/wg0.conf"):
            return False

        # Check for init script (critical for auto-start)
        if not fileExists("/etc/init.d/wireguard"):
            return False

        # If both exist, consider it installed
        return True

    def install(self):
        message = (
            "This will install WireGuard VPN server.\n\n"
            "The installation will:\n"
            "• Install packages (wireguard-tools, iptables)\n"
            "• Generate security keys\n"
            "• Configure firewall\n"
            "• Enable auto-start\n\n"
            "Takes 2-3 minutes. Continue?"
        )
        self.session.openWithCallback(
            self.installConfirmed,
            MessageBox,
            message,
            MessageBox.TYPE_YESNO,
            default=True
        )

    def installConfirmed(self, answer):
        if answer:
            self.session.open(
                WireGuardInstaller,
                mode="install"
            )

    def reinstall(self):
        message = (
            "Reinstall WireGuard while preserving keys.\n\n"
            "Your VPN will continue working without reconfiguring clients.\n\n"
            "Continue?"
        )
        self.session.openWithCallback(
            self.reinstallConfirmed,
            MessageBox,
            message,
            MessageBox.TYPE_YESNO,
            default=False
        )

    def reinstallConfirmed(self, answer):
        if answer:
            self.session.open(
                WireGuardInstaller,
                mode="reinstall"
            )

    def uninstall(self):
        message = (
            "WARNING: This will completely remove WireGuard!\n\n"
            "All keys, configs, and firewall rules deleted.\n"
            "You'll need to reconfigure clients if you reinstall.\n\n"
            "Required if installing commercial WireGuard clients.\n\n"
            "Are you SURE?"
        )
        self.session.openWithCallback(
            self.uninstallConfirmed,
            MessageBox,
            message,
            MessageBox.TYPE_YESNO,
            default=False
        )

    def uninstallConfirmed(self, answer):
        if answer:
            self.session.open(
                WireGuardInstaller,
                mode="uninstall"
            )

    def showStatus(self):
        self.session.open(WireGuardStatus)


class WireGuardStatus(Screen):
    """Status display - uses ScrollLabel for automatic skin adaptation"""

    # Minimal skin - ScrollLabel adapts automatically
    skin = """
        <screen name="WireGuardStatus" position="center,center" size="700,500" title="WireGuard Status">
            <widget name="output" position="10,10" size="680,450" font="Console;18" />
            <widget name="actions" position="10,470" size="680,20" font="Regular;16" halign="center" />
        </screen>
    """

    def __init__(self, session):
        Screen.__init__(self, session)
        self.session = session
        self.console = Console()

        self["output"] = ScrollLabel("")
        self["actions"] = Label("BLUE = Close | UP/DOWN = Scroll")

        self["actions"] = ActionMap(["ColorActions", "OkCancelActions", "DirectionActions"], {
            "blue": self.close,
            "cancel": self.close,
            "up": self["output"].pageUp,
            "down": self["output"].pageDown
        }, -1)

        self.getStatus()

    def getStatus(self):
        self["output"].setText("Loading WireGuard status...\n")
        cmd = "wg show; echo '\n--- Configuration ---'; cat /etc/wireguard/wg0.conf 2>/dev/null || echo 'No config found'"
        self.console.ePopen(cmd, self.statusCallback)

    def statusCallback(self, result, retval, extra_args=None):
        if result:
            self["output"].setText(result)
        else:
            self["output"].setText("Error: Could not retrieve WireGuard status")


class WireGuardInstaller(Screen):
    """Installer screen - uses ScrollLabel for console output"""

    # Minimal skin - automatic adaptation
    skin = """
        <screen name="WireGuardInstaller" position="center,center" size="800,600" title="WireGuard Installation">
            <widget name="output" position="10,10" size="780,550" font="Console;18" />
            <widget name="status" position="10,570" size="780,20" font="Regular;18" halign="center" />
        </screen>
    """

    def __init__(self, session, mode="install"):
        Screen.__init__(self, session)
        self.session = session
        self.console = Console()
        self.mode = mode  # install, reinstall, or uninstall

        self["output"] = ScrollLabel("")
        self["status"] = Label("Starting...")

        self["actions"] = ActionMap(["OkCancelActions", "DirectionActions"], {
            "ok": self.close,
            "cancel": self.close,
            "up": self["output"].pageUp,
            "down": self["output"].pageDown
        }, -1)

        self.outputText = ""
        self.onLayoutFinish.append(self.startProcess)

    def startProcess(self):
        plugin_dir = "/usr/lib/enigma2/python/Plugins/Extensions/WireGuardTNAP"

        if self.mode == "uninstall":
            self["status"].setText("Uninstalling WireGuard...")
            script = os.path.join(plugin_dir, "wireguard-uninstall.sh")
            cmd = f"sh {script}"
        else:
            if self.mode == "reinstall":
                self["status"].setText("Reinstalling WireGuard...")
            else:
                self["status"].setText("Installing WireGuard...")
            script = os.path.join(plugin_dir, "wireguard-install.sh")
            cmd = f"sh {script}"

        self.appendOutput(f"Running: {cmd}\n\n")
        self.console.ePopen(cmd, self.processCallback)

    def appendOutput(self, text):
        self.outputText += text
        self["output"].setText(self.outputText)
        # Auto-scroll to bottom
        self["output"].lastPage()

    def processCallback(self, result, retval, extra_args=None):
        if result:
            self.appendOutput(result)

        if retval == 0:
            if self.mode == "uninstall":
                self["status"].setText("Uninstall completed! Press OK to close.")
                self.appendOutput("\n\n=== WireGuard Uninstalled ===\n")
                self.appendOutput("You can now install commercial WireGuard clients.\n")
            else:
                self["status"].setText("Installation completed! Press OK to close.")
                self.appendOutput("\n\n=== Installation Complete ===\n")
                self.appendOutput("Next steps:\n")
                self.appendOutput("1. Router port forwarding (UDP 51820)\n")
                self.appendOutput("2. Copy /etc/wireguard/client_phone.conf to phone\n")
                self.appendOutput("3. Install WireGuard app and import config\n")
        else:
            self["status"].setText("ERROR! Check output. Press OK to close.")
            self.appendOutput(f"\n\nERROR: Process failed with code {retval}\n")


def main(session, **kwargs):
    session.open(WireGuardSetup)


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
