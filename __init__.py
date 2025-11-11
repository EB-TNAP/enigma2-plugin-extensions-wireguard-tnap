# WireGuard TNAP Server Plugin
from Components.Language import language
from Tools.Directories import resolveFilename, SCOPE_PLUGINS
import gettext

def localeInit():
    gettext.bindtextdomain("WireGuardTNAP", resolveFilename(SCOPE_PLUGINS, "Extensions/WireGuardTNAP/locale"))

def _(txt):
    if gettext.dgettext("WireGuardTNAP", txt):
        return gettext.dgettext("WireGuardTNAP", txt)
    else:
        return gettext.gettext(txt)

localeInit()
language.addCallback(localeInit)
