from web3 import Web3, HTTPProvider, IPCProvider
import json
import time
import argparse

def http_provider(endpoint_uri):
    web3 = Web3(HTTPProvider(endpoint_uri))
    return web3

def trusted_keys():
    keys = contract.call().keys(account)
    signatures_count = contract.call().getSignaturesLength(account)

    for i in range(signatures_count):
        signature = contract.call().getSignature(account, i)
        yield signature

def display_trusted_keys(args):
    for key in trusted_keys():
        print('signature={} (expires@{})'.format(key[0], key[1]))

def trust(args):
    contract.call({'from': account}).signKey(args.key, args.expiry)
    tr = contract.transact({'from': account}).signKey(args.key, args.expiry)
    return tr

parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--json-rpc", default='http://localhost:8545', dest='web3', type=http_provider, help="web3 HTTP provider")
account_group = parser.add_mutually_exclusive_group()
account_group.add_argument('--coinbase', action='store_true')
account_group.add_argument('--account', help='eth account')
#parser.add_argument('--coinbase', dest='coinbase', action='store_true', help="use coinbase")
#parser.set_defaults(coinbase=False)
#parser.add_argument("--account", default='coinbase', help="eth account")
#parser.add_argument("--account", action=AccountAction, default="coinbase", help="account")
subparsers = parser.add_subparsers(help='sub-command help')
parser_trust = subparsers.add_parser(name="trust", help="trust a secp256k1 public key")
parser_trust.add_argument("key", help="key to trust")
parser_trust.add_argument("--expiry", default=2**256 - 1, help="expiry")
parser_trust.set_defaults(func=trust)
parser_auth = subparsers.add_parser(name="validate", help="authenticate a secp256k1 public key")
parser_distrust = subparsers.add_parser(name="distrust", help="revoke trust on a secp256k1 public key")
parser_keys = subparsers.add_parser(name="list", help="display account trusted public keys")
parser_keys.set_defaults(func=display_trusted_keys)
parser_keys = subparsers.add_parser(name="plot", help="plot the web of trust graph")
parser_revoke = subparsers.add_parser(name="revoke", help="revoke your public key")
parser_revoke.add_argument("--key", help="revocation key")
args = parser.parse_args()
web3 = args.web3
if not args.account:
    account = web3.eth.coinbase
else:
    account = args.account

print('args.account: %s' % args.account)
print('args.coinbase: %s' % args.coinbase)
#coinbase = web3.eth.coinbase
balance = web3.eth.getBalance(account)
#print(balance)
print(web3.eth.blockNumber)

with open('build/contracts/DPKI.json') as definition_f:
    definition = json.load(definition_f)

abi = definition['abi']
print(abi)

contract = web3.eth.contract(abi=abi, address='0xcfeb869f69431e42cdb54a4f4f105c19c080a601')
print('contract: %s' % contract)

args.func(args)
