#!/usr/bin/env python3

import os
import sys
import getpass
import json

from colorama import Fore, Back, Style
import click

from bst.store import Store
from bst import utils
from bst import cryptutils

from bigchaindb_driver import BigchainDB

CONFIG = {}
ENDPOINT = os.environ.get('BIGCHAINDB_HOST', 'http://localhost:9984')
APP_ID = os.environ.get('BIGCHAINDB_APP_ID')
APP_KEY = os.environ.get('BIGCHAINDB_APP_KEY')

if APP_ID and APP_KEY:
    headers = {'app_id': APP_ID,
               'app_key': APP_KEY}
else:
    headers = {}

bdb = BigchainDB(ENDPOINT, headers=headers)


def resolve(ctx, param, value):
    return cryptutils.resolve(value)


@click.group()
@click.option('-k', '--keypair', default=getpass.getuser)
def cli(keypair):
    try:
        CONFIG['keypair'] = cryptutils.load_keypair(keypair)
    except FileNotFoundError:
        pass
    CONFIG['store'] = Store(keypair)


@cli.command()
@click.argument('infile', type=click.File('r'))
def encrypt(infile):
    keypair = CONFIG['keypair']
    store = CONFIG['store']

    asset = json.load(infile)
    key = cryptutils.random()
    cipher = cryptutils.encrypt(asset, key)
    tx = bdb.transactions.prepare(
        operation='CREATE',
        signers=keypair['verify_b58'],
        asset={'data': {'op': 'encrypt', 'cipher': cipher}})
    tx = bdb.transactions.fulfill(tx, private_keys=keypair['sign_b58'])
    bdb.transactions.send(tx)

    store.set(tx['id'], cryptutils.to_b64(key)).sync()

    print(tx['id'], cryptutils.to_b64(key))


@cli.command()
@click.argument('infile', type=click.File('r'))
def anonymize(infile):
    store = CONFIG['store']

    anon_keypair = cryptutils.keypair(seed=b'\1'*32)
    asset = json.load(infile)
    key = cryptutils.random()
    asset['op'] = 'anon:create'
    asset['ts'] = utils.now()
    asset['proof_hash'] = cryptutils.hash(key)

    # IMO the signature is useless here
    # asset['proof_sig'] = cryptutils.encrypt(cryptutils.sign(key, keypair['sign']), key)

    tx = bdb.transactions.prepare(operation='CREATE',
                                  signers=anon_keypair['verify_b58'],
                                  asset={'data': asset})
    tx = bdb.transactions.fulfill(tx, private_keys=anon_keypair['sign_b58'])
    bdb.transactions.send(tx)

    store.set(tx['id'], cryptutils.to_b64(key)).sync()

    print(tx['id'], cryptutils.to_b64(key))


@cli.command()
@click.argument('recipient', callback=resolve)
@click.argument('txid')
def transfer(recipient, txid):
    tx = bdb.transactions.retrieve(txid)
    anon_keypair = cryptutils.keypair(seed=b'\1'*32)
    if tx['inputs'][0]['owners_before'][0] == anon_keypair['verify_b58']:
        transfer_anonymize(recipient, tx)
    else:
        transfer_secret(recipient, tx)


def transfer_anonymize(recipient, tx):
    keypair = CONFIG['keypair']
    store = CONFIG['store']
    recipient_public_key = utils.retrieve_public_key(bdb, recipient)
    txid = tx['id']

    asset = {'valid_from': utils.now(),
             'valid_to': utils.now(weeks=2),
             'transactions': [(txid, store.get(txid))]}

    key = cryptutils.random()
    cipher = cryptutils.encrypt(asset, key)
    encrypted_key = cryptutils.pkencrypt(key,
                                         keypair['private_b58'],
                                         recipient_public_key)

    create_tx = bdb.transactions.prepare(operation='CREATE',
                                         signers=keypair['verify_b58'],
                                         asset={'data': {'op': 'anon:transfer',
                                                         'cipher': cipher,
                                                         'key': encrypted_key}})

    create_tx = bdb.transactions.fulfill(create_tx, private_keys=keypair['sign_b58'])
    bdb.transactions.send(create_tx)

    utils.wait_until_valid(bdb, create_tx)

    # Prepare transfer
    output_index = 0
    output = create_tx['outputs'][output_index]
    transfer_input = {'fulfillment': output['condition']['details'],
                      'fulfills': {'output': output_index,
                                   'txid': create_tx['id']},
                      'owners_before': output['public_keys']}
    transfer_tx = bdb.transactions.prepare(operation='TRANSFER',
                                           asset={'id': create_tx['id']},
                                           inputs=transfer_input,
                                           recipients=recipient)
    transfer_tx = bdb.transactions.fulfill(transfer_tx,
                                           private_keys=keypair['sign_b58'])

    bdb.transactions.send(transfer_tx)

    print(transfer_tx['id'])


@cli.command()
@click.argument('txid')
@click.argument('key')
def decrypt(txid, key):
    tx = bdb.transactions.retrieve(txid)
    key = cryptutils.from_b64(key)
    cipher = cryptutils.from_b64(tx['asset']['data']['cipher'])
    print(cryptutils.decrypt(cipher, key))


@cli.command()
def keys():
    keypair = CONFIG['keypair']
    print('*** PUBLIC KEYS ***')
    print('verify\t{}'.format(keypair['verify_b58']))
    print('public\t{}'.format(keypair['public_b58']))
    print()
    print('*** PRIVATE KEYS ***')
    print('sign\t{}'.format(keypair['sign_b58']))
    print('private\t{}'.format(keypair['private_b58']))


@cli.command()
def publish_key():
    keypair = CONFIG['keypair']
    tx = bdb.transactions.prepare(
        operation='CREATE',
        signers=keypair['verify_b58'],
        asset={'data': {'op': 'wot:publish',
                        'dt': utils.now(),
                        'public_key': keypair['public_b58'] }})
    tx = bdb.transactions.fulfill(tx, private_keys=keypair['sign_b58'])
    bdb.transactions.send(tx)
    print('Verifying Key {} is now connected to '
          'Public Key {}'.format(Fore.YELLOW + keypair['verify_b58'] + Style.RESET_ALL,
                                 Fore.YELLOW + keypair['public_b58'] + Style.RESET_ALL))
    print('Proof', Fore.GREEN + tx['id'])


@cli.command()
@click.argument('identity', callback=resolve)
def retrieve_key(identity):
    tx = utils.retrieve_public_key_transaction(bdb, identity)
    verify_b58 = tx['outputs'][0]['public_keys'][0]
    public_b58 = tx['asset']['data'].get('public_key')
    print('Verifying Key {} is connected to '
          'Public Key {}'.format(Fore.YELLOW + verify_b58 + Style.RESET_ALL,
                                 Fore.YELLOW + public_b58 + Style.RESET_ALL))
    print('Proof', Fore.GREEN + tx['id'])


@cli.command()
@click.argument('identity', default=getpass.getuser)
def create_keypair(identity):
    try:
        cryptutils.load_keypair(identity)
        sys.exit('A keypair with identity `{}` already exists.'.format(identity))
    except FileNotFoundError:
        cryptutils.create_keypair(identity)


@cli.command()
@click.argument('identity', callback=resolve)
def resolve(identity):
    print(identity)


@cli.command()
@click.option('--show-asset', is_flag=True)
def unspents(show_asset):
    keypair = CONFIG['keypair']
    unspents = map(lambda x: x.split('/')[2],
                   bdb.outputs.get(keypair['verify_b58'], unspent=True))

    for txid in unspents:
        if show_asset:
            tx = bdb.transactions.retrieve(txid)
            tx_asset = tx['asset']
            try:
                tx_data = tx_asset['data']
                print(txid)
            except KeyError:
                tx_data = bdb.transactions.retrieve(tx_asset['id'])['asset']['data']
                print('{} (from: {})'.format(txid, tx_asset['id']))

            print(json.dumps(tx_data,
                             sort_keys=True,
                             indent=2))
            print()
        else:
            print(txid)


@cli.command()
@click.option('--show-asset', is_flag=True)
def unspents_anon(show_asset):
    keypair = CONFIG['keypair']
    unspents = map(lambda x: x.split('/')[2],
                   bdb.outputs.get(keypair['verify_b58'], unspent=True))

    for txid in unspents:
        tx = bdb.transactions.retrieve(txid)
        tx_asset = tx['asset']
        try:
            tx_data = tx_asset['data']
        except KeyError:
            tx_data = bdb.transactions.retrieve(tx_asset['id'])['asset']['data']

        if tx_data.get('op') != 'anon:transfer':
            continue

        sender_verify_key = tx['inputs'][0]['owners_before'][0]
        sender_public_key = utils.retrieve_public_key(bdb, sender_verify_key)

        decrypt_key = cryptutils.pkdecrypt(tx_data['key'],
                                           sender_public_key,
                                           keypair['private_b58'])

        payload = cryptutils.decrypt(cryptutils.from_b64(tx_data['cipher']),
                                     decrypt_key)

        for payload_tx, payload_key in payload['transactions']:
            shared_tx = bdb.transactions.retrieve(payload_tx)
            proof_hash = shared_tx['asset']['data']['proof_hash']
            payload_key = cryptutils.from_b64(payload_key)
            key_hash = cryptutils.hash(payload_key)
            if proof_hash != key_hash:
                raise ValueError

        print(txid)
        if show_asset:
            print(json.dumps(payload,
                             sort_keys=True,
                             indent=2))
            print()


@cli.command()
@click.argument('txid')
def tx(txid):
    print(json.dumps(bdb.transactions.retrieve(txid),
                     sort_keys=True,
                     indent=2))


@cli.command()
@click.argument('txid')
def asset(txid):
    tx = bdb.transactions.retrieve(txid)
    tx_asset = tx['asset']
    try:
        tx_data = tx_asset['data']
    except KeyError:
        tx_data = bdb.transactions.retrieve(tx_asset['id'])['asset']['data']
    print(json.dumps(tx_data, sort_keys=True, indent=2))


def main():
    cli()


if __name__ == '__main__':
    main()
