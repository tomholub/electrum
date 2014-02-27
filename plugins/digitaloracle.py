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

from electrum_gui.qt.qrcodewidget import QRCodeWidget

from random import SystemRandom
from base64 import b32encode

class Plugin(BasePlugin):

    def fullname(self):
        return _('CryptoCorp Digital Oracle')

    def description(self):
        return _("This plugin allows the creation of a multi-signature account with one key implementing specific business rules.")

    def version(self):
        return "0.0.1"

    def init(self):
        self.window = self.gui.main_window
        self.window.deferral_question = self.deferral_question
        cryptocorp.set_recovery_mode(self.recovery())

    def deferral_question(self, de):
        d = QDialog()
        layout = QGridLayout(d)
        label = QLabel(str(de))
        label.setWordWrap(True)
        layout.addWidget(label,0,0,1,2)

        otp = None

        if 'otp' in de.verifications:
            layout.addWidget(QLabel("One time password: "),1,0)

            otp = QLineEdit()

            layout.addWidget(otp, 1,1)

        resubmit = QPushButton(_("Resubmit"))
        resubmit.clicked.connect(d.accept)

        c = QPushButton(_("Cancel"))
        c.clicked.connect(d.reject)

        layout.addWidget(resubmit,2,2)
        layout.addWidget(c,2,1)

        if d.exec_():
            if otp:
                de.otp = str(otp.text())
            return True
        else:
            return False

    def load_wallet(self, wallet):
        self.init()
        self.wallet = wallet
        self.window.new_account.triggered.disconnect(self.window.new_account_dialog)
        self.window.new_account.triggered.connect(self.new_account_dialog)

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def base_url(self):
        return self.config.get("base_url", "https://s.digitaloracle.co/")

    def recovery(self):
        return self.config.get("recovery", False)

    def requires_settings(self):
        return True

    def settings_dialog(self):
        def check_url(url):
            pass

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

        self.recovery_box = QCheckBox(_(""))
        self.recovery_box.setCheckState(Qt.Checked if self.recovery() else Qt.Unchecked)

        layout.addWidget(self.recovery_box,2,1)
        label = QLabel(_("Recovery: in this mode transactions are to be signed by the recovery key. The Oracle will not be contacted"))
        label.setWordWrap(True)
        layout.addWidget(label, 2, 0)
        layout.addWidget(c,4,1)
        layout.addWidget(self.accept,4,2)

        check_url(self.base_url())

        if d.exec_():
          self.config.set_key("base_url", str(self.url_edit.text()))
          self.config.set_key("recovery", self.recovery_box.checkState() == Qt.Checked)

          cryptocorp.set_recovery_mode(self.recovery())
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

        vbox.addWidget(QLabel(_('Email (optional)')+':'))
        email = QLineEdit()
        vbox.addWidget(email)

        vbox.addWidget(QLabel(_('Phone (optional)')+':'))
        phone = QLineEdit()
        vbox.addWidget(phone)

        vbox.addWidget(QLabel(_('Velocity limit')+':'))
        velocity_1 = QLineEdit("0.002")
        vbox.addWidget(velocity_1)

        vbox.addWidget(QLabel(_('Delay')+':'))
        delay_2 = QLineEdit("60")
        vbox.addWidget(delay_2)

        hbox = QHBoxLayout()
        vbox1 = QVBoxLayout()
        hbox.addLayout(vbox)
        hbox.addLayout(vbox1)

        vbox1.addWidget(QLabel(_('Backup Key (xpub)')+':'))
        #backup = QLineEdit()
        backup = QLineEdit('xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH')
        vbox1.addWidget(backup)

        vbox1.addWidget(QLabel(_('OTP (optional)')+':'))

        otp = QLineEdit()
        vbox1.addWidget(otp)

        qrw = QRCodeWidget()
        vbox1.addWidget(qrw)

        otp_secret = b32encode(("%x"%(SystemRandom().getrandbits(120))).decode('hex'))
        print otp_secret

        def check_name():
            if (str(e.text()) != ""):
                qrw.set_addr("otpauth://totp/Digital-Oracle-%s?secret=%s"%(e.text(), otp_secret))
            else:
                qrw.set_addr("")
            qrw.update_qr()

        e.textChanged.connect(check_name)
        check_name()

        vbox.addLayout(ok_cancel_buttons(dialog))
        dialog.setLayout(hbox)
        r = dialog.exec_()
        if not r: return

        name = str(e.text())
        if not name: return

        email_text = str(email.text())
        phone_text = str(phone.text())
        velocity_1_text = str(velocity_1.text())
        delay_2_text = str(delay_2.text())
        backup_text = str(backup.text())
        otp_text = str(otp.text())
        parameters = {
                'velocity_1': {
                    'value': float(velocity_1_text),
                    'asset': 'BTC',
                    'period': 60,
                    'limited_keys': [0],
                    },
                'delay_2': (int(delay_2_text) if delay_2_text != "" else None)
                }
        if phone_text and phone_text != "":
            parameters['call_2'] = ['phone', 'email']
            # TODO

        if otp_text and otp_text != "":
            parameters['otp'] = otp_text
            parameters['otp_secret'] = otp_secret
            parameters['otp_type'] = 'totp'
            parameters['verify_2'] = ['otp']

        pii = {
                "phone": phone_text,
                "email": email_text
                }

        if backup_text:
            account_id, i, c0, K0, cK0, my_key = self.wallet.next_oracle_account()
            oracle_url = cryptocorp.make_keychain(self.base_url(), my_key, backup_text, parameters, pii)
            self.wallet.create_oracle_account(oracle_url, my_key, backup_text, name)
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
