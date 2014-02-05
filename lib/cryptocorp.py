import struct
import bitcoin
import ecdsa
import account
from ecdsa.curves import SECP256k1
from wallet import Wallet

PRIVATE_TEST_VERSION = [
    ( True, False, "0488ADE4"),
    (False, False, "0488B21E"),
    ( True,  True, "04358394"),
    (False,  True, "043587CF"),
]

# generate lookup and reverse lookup
PRIVATE_TEST__VERSION_LOOKUP = dict(((p, t), v.decode("hex")) for p, t, v in PRIVATE_TEST_VERSION)
VERSION__PRIVATE_TEST_LOOKUP = dict((v.decode("hex"), (p, t)) for p, t, v in PRIVATE_TEST_VERSION)


def SerializeExtendedPublicKey(depth, parent_fingerprint, child_number, chain_code, cK):
    """Yield a base58 encoded 78-byte binary blob corresponding to this node."""

    vch = PRIVATE_TEST__VERSION_LOOKUP[(False, False)]
    vch += chr(depth)
    vch += parent_fingerprint
    vch += struct.pack(">L", child_number)
    vch += chain_code
    #    ba += b'\0' + self.secret_exponent_bytes
    vch += cK
    return bitcoin.EncodeBase58Check(vch)

def DeserializeExtendedKey(s):
    """Decode 78-byte binary blob corresponding to this node."""

    data = bitcoin.DecodeBase58Check(s)
    (is_private, is_test) = VERSION__PRIVATE_TEST_LOOKUP[data[0:4]]
    parent_fingerprint = data[5:9]
    child_number, = struct.unpack(">L", data[9:13])
    d = dict(is_private=is_private, is_test=is_test, chain_code=data[13:45], depth=ord(data[4]), parent_fingerprint=parent_fingerprint, child_number=child_number)
    if is_private:
        if ord(data[45]) != 0:
            raise Exception("incorrect private key encoding")
        d['secret'] = data[46:]
    else:
        Q = bitcoin.ser_to_point(data[45:])
        pubkey = ecdsa.VerifyingKey.from_public_point(Q, curve = SECP256k1)
        d['K'] = pubkey.to_string()
        d['cK'] = bitcoin.GetPubKey(pubkey.pubkey, True)
    return d

class Oracle_Account(account.BIP32_Account_2of3):
    def __init__(self, v):
        self.oracle = v['oracle']
        self.backup = v['backup']
        oracle = DeserializeExtendedKey(v['oracle'])
        backup = DeserializeExtendedKey(v['backup'])
        v['c2'] = backup['chain_code'].encode('hex')
        v['K2'] = backup['K'].encode('hex')
        v['cK2'] = backup['cK'].encode('hex')
        v['c3'] = oracle['chain_code'].encode('hex')
        v['K3'] = oracle['K'].encode('hex')
        v['cK3'] = oracle['cK'].encode('hex')
        print "derived="
        print SerializeExtendedPublicKey(2, "00000000".decode('hex'), 0, v['c'].decode('hex'), v['cK'].decode('hex'))
        account.BIP32_Account_2of3.__init__(self, v)

    def dump(self):
        d = account.BIP32_Account_2of3.dump(self)
        d['oracle'] = self.oracle
        d['backup'] = self.backup
        return d
