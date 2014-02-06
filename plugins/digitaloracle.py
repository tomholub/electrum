from electrum.util import print_error

import httplib, urllib
import socket
import hashlib
import json
from urlparse import urlparse, parse_qs
try:
    import PyQt4
except Exception:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
from gui.qt.util import ok_cancel_buttons
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui
from electrum.plugins import BasePlugin
from electrum.i18n import _

from electrum_gui.qt import HelpButton, EnterButton

from electrum import cryptocorp

class Plugin(BasePlugin):

    def fullname(self):
        return _('CryptoCorp Digital Oracle')

    def description(self):
        return _("This plugin allows the creation of a multi-signature account with one key implementing specific business rules.")

    def version(self):
        return "0.0.1"

    def init(self):
        self.window = self.gui.main_window

    def load_wallet(self, wallet):
        self.init()
        self.wallet = wallet
        self.window.new_account.triggered.disconnect(self.window.new_account_dialog)
        self.window.new_account.triggered.connect(self.new_account_dialog)
        print "load_wallet"

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def base_url(self):
        return self.config.get("base_url", "http://btc2.hyper.to/")

    def requires_settings(self):
        return True

    def settings_dialog(self):
        def check_url(url):
            self.config.set_key("base_url", str(self.url_edit.text()))
            print url

        d = QDialog()
        layout = QGridLayout(d)
        layout.addWidget(QLabel("Oracle base URL: "),0,0)

        self.url_edit = QLineEdit(self.base_url())
        self.url_edit.textChanged.connect(check_url)

        layout.addWidget(self.url_edit, 0,1,1,2)

        c = QPushButton(_("Cancel"))
        c.clicked.connect(d.reject)

        self.accept = QPushButton(_("Done"))
        self.accept.clicked.connect(d.accept)

        layout.addWidget(c,3,1)
        layout.addWidget(self.accept,3,2)

        check_url(self.base_url())

        if d.exec_():
          return True
        else:
          return False

    def enable(self):
        self.load_wallet(self.gui.main_window.wallet)
        self.set_enabled(True)
        return True

    def new_account_dialog(self):
        dialog = QDialog(self.window)
        dialog.setModal(1)
        dialog.setWindowTitle(_("New Account"))

        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_('Account name')+':'))
        e = QLineEdit()
        vbox.addWidget(e)

        msg = _("Please fill in the fields below for Oracle accounts:")
        l = QLabel(msg)
        l.setWordWrap(True)
        vbox.addWidget(l)

        vbox.addWidget(QLabel(_('Email')+':'))
        email = QLineEdit()
        vbox.addWidget(email)

        vbox.addWidget(QLabel(_('Phone')+':'))
        phone = QLineEdit()
        vbox.addWidget(phone)

        vbox.addWidget(QLabel(_('Velocity limit')+':'))
        velocity_1 = QLineEdit("0.002")
        vbox.addWidget(velocity_1)

        vbox.addWidget(QLabel(_('Delay')+':'))
        delay_2 = QLineEdit("60")
        vbox.addWidget(delay_2)

        vbox.addWidget(QLabel(_('Backup Key (xpub)')+':'))
        #backup = QLineEdit()
        backup = QLineEdit('xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH')
        vbox.addWidget(backup)

        vbox.addLayout(ok_cancel_buttons(dialog))
        dialog.setLayout(vbox)
        r = dialog.exec_()
        if not r: return

        name = str(e.text())
        if not name: return

        email_text = str(email.text())
        phone_text = str(phone.text())
        velocity_1_text = str(velocity_1.text())
        delay_2_text = str(delay_2.text())
        backup_text = str(backup.text())
        parameters = {
                'velocity_1': {
                    'value': float(velocity_1_text),
                    'asset': 'BTC',
                    'period': 60,
                    'limited_keys': [0],
                    },
                'delay_2': (int(delay_2_text) if delay_2_text != "" else None),
                'call_2': ['phone', 'email']
                }
        pii = {
                "phone": phone_text,
                "email": email_text
                }

        if backup_text:
            account_id, i, c0, K0, cK0, my_key = self.wallet.next_oracle_account()
            oracle_url = cryptocorp.make_keychain(self.base_url(), my_key, backup_text, parameters, pii)
            self.wallet.create_oracle_account(oracle_url, backup_text, name)
        else:
            self.wallet.create_pending_account('1', name)

        self.window.update_receive_tab()
        self.window.tabs.setCurrentIndex(2)


def debug_trace():
  '''Set a tracepoint in the Python debugger that works with Qt'''
  from PyQt4.QtCore import pyqtRemoveInputHook
  from pdb import set_trace
  pyqtRemoveInputHook()
  set_trace()
