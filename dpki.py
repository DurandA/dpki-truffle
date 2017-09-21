#!/usr/bin/env python3
from web3 import Web3, HTTPProvider, IPCProvider
import json
import sys, io, time
import argparse
import six

def http_provider(endpoint_uri):
    web3 = Web3(HTTPProvider(endpoint_uri))
    return web3

def trusted_keys():
    keys = contract.call().keys(account)
    # TODO use generated getter
    signatures_count = contract.call().getSignaturesLength(account)

    for i in range(signatures_count):
        signature = contract.call().getSignature(account, i)
        yield signature

def display_trusted_keys(args):
    for key in trusted_keys():
        print('signature={} (expires@{})'.format(key[0], key[1]))

def trust(args):
    address = str(args.address)
    contract.call({'from': account}).signKey(address, args.expiry)
    tr = contract.transact({'from': account}).signKey(address, args.expiry)
    return tr

from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ecdsa import SigningKey as _ECDSA_SigningKey, SECP256k1, VerifyingKey as _ECDSA_VerifyingKey
from ecdsa.ellipticcurve import Point as _ECDSA_Point

import sha3

class SigningKey(_ECDSA_SigningKey):
    pass

class VerifyingKey(_ECDSA_VerifyingKey):

    @classmethod
    def from_cert_file(cls, certificate_file):
        with open(certificate_file, 'rb') as pem:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem.read())
        return cls.from_cert(cert)

    @classmethod
    def from_cert(cls, certificate):
        assert certificate.get_signature_algorithm().decode() == 'ecdsa-with-SHA256'
        pubkey = certificate.get_pubkey().to_cryptography_key()
        assert isinstance(pubkey.curve, ec.SECP256K1)
        pub_vars = pubkey.public_numbers()
        point = cls.create_point(pub_vars.x, pub_vars.y)
        return VerifyingKey.from_public_point(point, curve=SECP256k1)

    # https://www.reddit.com/r/ethereum/comments/6pv1dx/how_to_generate_an_ethereum_wallet_the_hard_way/
    def to_address(self):
        keccak = sha3.keccak_256()
        keccak.update(self.to_string())
        return "0x{0}".format(keccak.hexdigest()[24:])

    def __str__(self):
        return self.to_address()

    # http://nullege.com/codes/show/src@b@i@bitmerchant-0.1.3@bitmerchant@wallet@keys.py/323/ecdsa.VerifyingKey.from_public_point
    @staticmethod
    def create_point(x, y):
        """Create an ECDSA point on the SECP256k1 curve with the given coords.

        :param x: The x coordinate on the curve
        :type x: long
        :param y: The y coodinate on the curve
        :type y: long
        """
        if (not isinstance(x, six.integer_types) or
                not isinstance(y, six.integer_types)):
            raise ValueError("The coordinates must be longs.")
        return _ECDSA_Point(SECP256k1.curve, x, y)

def authenticate(args):
    address = str(args.address)
    print("Authenticating {}...".format(address), end=' ')
    # TODO replace operator by generator
    import operator
    if address not in map(operator.itemgetter(0), trusted_keys()):
        raise UserWarning('%s is untrusted.' % address)
    print('Authenticated!')
    return True

parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--json-rpc", default='http://localhost:8545', dest='web3', type=http_provider, help="web3 HTTP provider")
account_group = parser.add_mutually_exclusive_group()
#account_group.add_argument('--coinbase', action='store_true')
account_group.add_argument('--account', help='eth account')
#parser.add_argument('--coinbase', dest='coinbase', action='store_true', help="use coinbase")
#parser.set_defaults(coinbase=False)
#parser.add_argument("--account", default='coinbase', help="eth account")
#parser.add_argument("--account", action=AccountAction, default="coinbase", help="account")
subparsers = parser.add_subparsers(help='sub-command help')
parser_trust = subparsers.add_parser(name="trust", help="trust a secp256k1 public key")
#parser_trust.add_argument("key", help="key to trust")
parser_trust.add_argument("--expiry", default=2**256 - 1, help="expiry")
parser_trust.set_defaults(func=trust)
parser_auth = subparsers.add_parser(name="auth", help="authenticate a X.509 certificate")
#parser_auth.add_argument("cert", help="x.509 certificate to check")
parser_auth.set_defaults(func=authenticate)
parser_distrust = subparsers.add_parser(name="distrust", help="revoke trust on a secp256k1 public key")
parser_keys = subparsers.add_parser(name="list", help="display account trusted public keys")
parser_keys.set_defaults(func=display_trusted_keys)
parser_keys = subparsers.add_parser(name="plot", help="plot the web of trust graph")
parser_revoke = subparsers.add_parser(name="revoke", help="revoke your public key")
parser_revoke.add_argument("--key", help="revocation key")
for subparser in [parser_trust, parser_auth]:
    key_group = subparser.add_mutually_exclusive_group()
    key_group.add_argument('--address', help='eth address')
    key_group.add_argument('--cert', dest='address', type=VerifyingKey.from_cert_file, help='X.509 certificate')

args = parser.parse_args()
web3 = args.web3
if not args.account:
    account = web3.eth.coinbase
else:
    account = args.account

print('Account: %s' % account)
#coinbase = web3.eth.coinbase
balance = web3.eth.getBalance(account)
#print(balance)
print('Block number: %i' % web3.eth.blockNumber)

with open('build/contracts/DPKI.json') as definition_f:
    definition = json.load(definition_f)

abi = definition['abi']

contract = web3.eth.contract(abi=abi, address='0xcfeb869f69431e42cdb54a4f4f105c19c080a601')
print('Contract: %s' % contract)

if 'func' not in args:
    parser.print_help()
    sys.exit(0)
args.func(args)
