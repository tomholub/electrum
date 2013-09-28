#!/usr/bin/env python
#
# serve.py - a simple JSON-RPC client/server that can serve wallet history
# Copyright (C) 2011 Tradehill Inc
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


import time, thread, sys, socket, os
import optparse

is_local = os.path.dirname(os.path.realpath(__file__)) == os.path.join(os.getcwd(), 'scripts')

import __builtin__
__builtin__.use_local_modules = is_local

# load local module as electrum
if __builtin__.use_local_modules:
    import imp
    imp.load_module('electrum', *imp.find_module('../lib'))

from electrum import Wallet, Interface, WalletVerifier, SimpleConfig, WalletSynchronizer, util
import ConfigParser

def arg_parser():
    usage = """usage: %prog [options] [COMMAND ARG ...]
A general purpose merchant daemon.  Commands:
    history [LENGTH=1000] - dump last LENGTH transactions
    new-address [LABEL] - allocates a new address, with an optional label
    validate-address [ADDRESS] - validates an address by signing a message and verifying
    stop - stops the server
""" 
    parser = optparse.OptionParser(prog=usage)
    parser.add_option("-w", "--wallet", dest="wallet_path", help="wallet path (default: electrum.dat)")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="show debugging information")
    return parser

config = ConfigParser.ConfigParser()
config.read("merchant.conf")

electrum_server = config.get('electrum','server')

my_host = config.get('main','host')
my_port = config.getint('main','port')

def on_wallet_update():
    print "updated_callback"

stopping = False

def shutdown_thread():
    global server
    server.shutdown()

def do_stop():
    thread.start_new_thread(shutdown_thread, ())
    return True

def process_history(length = 1000):
    print "process_history", length
    history = wallet.get_tx_history()[-length:]
    txs = map(lambda t: {'txid': t[0], 'confirmations': t[1], 'address': t[2], 'is_mine': t[3], 'amount': t[4], 'fee': t[5], 'balance': t[6], 'blocktime': t[7]}, history)
    return txs

def new_address(label = None, account_name = "m/0'/0'"):
    print "new_address", label
    account = wallet.accounts[account_name]
    address = wallet.create_new_address(account)
    if label:
        wallet.add_contact(address, label)
    return address

def validate_address(address):
    sig = wallet.sign_message(address, address, None)
    return wallet.verify_message(address, sig, address)

def server_thread(context):
    from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
    global server
    server = SimpleJSONRPCServer(( my_host, my_port))
    server.register_function(process_history, 'history')
    server.register_function(new_address, 'new_address')
    server.register_function(validate_address, 'validate_address')
    server.register_function(do_stop, 'stop')
    server.serve_forever()
    

def handle_command(cmd, args):
    import jsonrpclib
    server = jsonrpclib.Server('http://%s:%d'%(my_host, my_port))
    try:
        if cmd == 'stop':
            out = server.stop()
        elif cmd == 'history':
            if len(args) > 0:
                args[0] = int(args[0])
            out = server.history(*args)
        elif cmd == 'new-address':
            out = server.new_address(*args)
        elif cmd == 'validate-address':
            out = server.validate_address(*args)
        else:
            out = "unknown command"
    except socket.error:
        print "Server not running"
        return 1

    util.print_json(out)
    return 0


if __name__ == '__main__':
    parser = arg_parser()
    options, args = parser.parse_args()
    config_options = eval(str(options))
    wallet_config = SimpleConfig(config_options)
    wallet = Wallet(wallet_config)


    for k, v in config_options.items():
          if v is None: config_options.pop(k)

    if len(args) > 0:
        ret = handle_command(args[0], args[1:])
        sys.exit(ret)

    interface = Interface({'server':"%s:%d:t"%(electrum_server, 50001)})
    interface.start()
    interface.send([('blockchain.numblocks.subscribe',[])])

    wallet.interface = interface
    interface.register_callback('updated', on_wallet_update)

    verifier = WalletVerifier(interface, wallet_config)
    wallet.set_verifier(verifier)

    synchronizer = WalletSynchronizer(wallet, wallet_config)
    synchronizer.start()

    verifier.start()
    

    server_thread(None)
    print "terminated"


