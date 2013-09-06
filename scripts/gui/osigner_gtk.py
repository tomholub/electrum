#!/usr/bin/env python
#
# osigner UI
# Copyright (C) 2013 TradeHill Inc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import datetime
import thread, time, ast, sys, re
import socket, traceback
import pygtk
pygtk.require('2.0')
import gtk, gobject
from decimal import Decimal
from electrum.util import print_error
from electrum import is_valid
from electrum import Transaction

gtk.gdk.threads_init()
APP_NAME = "Electrum"
import platform
MONOSPACE_FONT = 'Lucida Console' if platform.system() == 'Windows' else 'monospace'

from electrum.util import format_satoshis

def show_message(message, parent=None):
    dialog = gtk.MessageDialog(
        parent = parent,
        flags = gtk.DIALOG_MODAL, 
        buttons = gtk.BUTTONS_CLOSE, 
        message_format = message )
    dialog.show()
    dialog.run()
    dialog.destroy()


class MyWindow(gtk.Window): __gsignals__ = dict( mykeypress = (gobject.SIGNAL_RUN_LAST | gobject.SIGNAL_ACTION, None, (str,)) )

gobject.type_register(MyWindow)
gtk.binding_entry_add_signal(MyWindow, gtk.keysyms.W, gtk.gdk.CONTROL_MASK, 'mykeypress', str, 'ctrl+W')
gtk.binding_entry_add_signal(MyWindow, gtk.keysyms.Q, gtk.gdk.CONTROL_MASK, 'mykeypress', str, 'ctrl+Q')


class OsignerWindow:

    def show_message(self, msg):
        show_message(msg, self.window)

    def __init__(self, wallet, config, scanner):
        self.scanner = scanner
        self.config = config
        self.wallet = wallet

        self.window = MyWindow(gtk.WINDOW_TOPLEVEL)
        title = 'Electrum Offline Signer ' + self.wallet.electrum_version + '  -  ' + self.config.path
        if not self.wallet.seed: title += ' [seedless]'
        self.window.set_title(title)
        self.window.connect("destroy", gtk.main_quit)
        self.window.set_border_width(0)
        self.window.connect('mykeypress', gtk.main_quit)
        self.window.set_default_size(720, 350)
        self.wallet_updated = False

        vbox = gtk.VBox()

        self.notebook = gtk.Notebook()
        self.create_txn_tab()
        self.create_about_tab()
        self.notebook.show()
        vbox.pack_start(self.notebook, True, True, 2)
        
        self.status_bar = gtk.Statusbar()
        vbox.pack_start(self.status_bar, False, False, 0)

        self.status_image = gtk.Image()
        self.status_image.set_from_stock(gtk.STOCK_NO, gtk.ICON_SIZE_MENU)
        self.status_image.set_alignment(True, 0.5  )
        self.status_image.show()

        self.window.add(vbox)
        self.window.show_all()

        self.context_id = self.status_bar.get_context_id("statusbar")
        self.update_status_bar()

        self.notebook.set_current_page(0)

    def update_callback(self):
        self.wallet_updated = True


    def add_tab(self, page, name):
        tab_label = gtk.Label(name)
        tab_label.show()
        self.notebook.append_page(page, tab_label)


    def question(self,msg):
        dialog = gtk.MessageDialog( self.window, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, msg)
        dialog.show()
        result = dialog.run()
        dialog.destroy()
        return result == gtk.RESPONSE_OK

    def treeview_button_press(self, treeview, event):
        if event.type == gtk.gdk._2BUTTON_PRESS:
            c = treeview.get_cursor()[0]
            if treeview == self.txn_treeview:
                tx_details = self.txn_list.get_value( self.txn_list.get_iter(c), 7)
                #self.show_message(tx_details)
                index = len(self.scanner.txs) - 1 - c[0]
                self.scanner.sign(self.scanner.txs[index])
                self.scanner.scan()
                self.update_txn_tab()
            

    def treeview_key_press(self, treeview, event):
        c = treeview.get_cursor()[0]
        if event.keyval == gtk.keysyms.Up:
            if c and c[0] == 0:
                treeview.parent.grab_focus()
                treeview.set_cursor((0,))
        return False

    def create_txn_tab(self):

        self.txn_list = gtk.ListStore(str, str, str, str, str, str, str, str, str)
        treeview = gtk.TreeView(model=self.txn_list)
        self.txn_treeview = treeview
        treeview.set_tooltip_column(7)
        treeview.show()
        treeview.connect('key-press-event', self.treeview_key_press)
        treeview.connect('button-press-event', self.treeview_button_press)

        tvcolumn = gtk.TreeViewColumn('')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererPixbuf()
        tvcolumn.pack_start(cell, False)
        tvcolumn.set_attributes(cell, stock_id=1)

        tvcolumn = gtk.TreeViewColumn('Date')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 2)

        tvcolumn = gtk.TreeViewColumn('File')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        cell.set_property('foreground', 'grey')
        cell.set_property('family', MONOSPACE_FONT)
        cell.set_property('editable', False)
        tvcolumn.set_expand(True)
        tvcolumn.pack_start(cell, True)
        tvcolumn.set_attributes(cell, text=3)

        tvcolumn = gtk.TreeViewColumn('Destination')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        cell.set_property('foreground', 'grey')
        cell.set_property('family', MONOSPACE_FONT)
        cell.set_property('editable', False)
        tvcolumn.set_expand(True)
        tvcolumn.pack_start(cell, True)
        tvcolumn.set_attributes(cell, text=4)

        tvcolumn = gtk.TreeViewColumn('Status')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        cell.set_property('foreground', 'grey')
        cell.set_property('family', MONOSPACE_FONT)
        cell.set_property('editable', False)
        tvcolumn.set_expand(True)
        tvcolumn.pack_start(cell, True)
        tvcolumn.set_attributes(cell, text=6)

        tvcolumn = gtk.TreeViewColumn('Amount')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        cell.set_alignment(1, 0.5)
        cell.set_property('family', MONOSPACE_FONT)
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 5)

        tvcolumn = gtk.TreeViewColumn('Tooltip')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 7)
        tvcolumn.set_visible(False)

        scroll = gtk.ScrolledWindow()
        scroll.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        scroll.add(treeview)

        self.add_tab(scroll, 'Transactions')
        self.update_txn_tab()

    def create_about_tab(self):
        import pango
        page = gtk.VBox()
        page.show()
        tv = gtk.TextView()
        tv.set_editable(False)
        tv.set_cursor_visible(False)
        tv.modify_font(pango.FontDescription(MONOSPACE_FONT))
        scroll = gtk.ScrolledWindow()
        scroll.add(tv)
        page.pack_start(scroll)
        self.info = tv.get_buffer()
        self.add_tab(page, 'Wall')


    def update_status_bar(self):
        self.status_bar.pop(self.context_id) 

    def update_txn_tab(self):
        cursor = self.txn_treeview.get_cursor()[0]
        self.txn_list.clear()

        for unsigned_tx in self.scanner.txs:
            time_str = datetime.datetime.fromtimestamp(unsigned_tx['created']).isoformat(' ')[:-3]
            tx_hash = 'pending'
            raw_tx = unsigned_tx['hex']
            tx = Transaction(raw_tx)
            conf_icon = None
            if not unsigned_tx['archived']:
                conf_icon = gtk.STOCK_APPLY if unsigned_tx['complete'] else gtk.STOCK_EXECUTE
            addresses = []
            label = unsigned_tx['file']
            value = 0
            all_addresses = map( lambda o: o[0], tx.outputs )
            tooltip = ""
            for out in tx.outputs:
                address, amount = out
                famount = format_satoshis(amount,True,self.wallet.num_zeros, whitespaces=True)
                if self.wallet.is_mine(address):
                    tooltip = tooltip + "%s CHANGE %s\n"%(address, famount)
                else:
                    tooltip = tooltip + "%s OUTPUT %s\n"%(address, famount)
                    value = value - amount
                    addresses.append(address)
            numsigs = 0
            for inp in tx.inputs:
                numsigs = max(numsigs, len(inp['signatures']))
                tooltip = tooltip + "%d sigs on %s\n"%(len(inp['signatures']), inp['address'])
            status = "%d sigs" %(numsigs)
            destination = ",".join(addresses)
            is_default_label = True
            details = "stuff happened"
            self.txn_list.prepend( [tx_hash, conf_icon, time_str, label, destination,
                                        format_satoshis(value,True,self.wallet.num_zeros, whitespaces=True),
                                        status, tooltip, details] )
        if cursor: self.txn_treeview.set_cursor( cursor )


class OsignerGui():

    def __init__(self, wallet, config, scanner):
        self.scanner = scanner
        self.wallet = wallet
        self.config = config

    def main(self):
        ew = OsignerWindow(self.wallet, self.config, self.scanner)
        gtk.main()

