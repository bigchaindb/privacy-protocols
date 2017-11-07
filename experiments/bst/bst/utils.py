import time
import datetime

import bigchaindb_driver

from bst import cryptutils


def now(weeks=0, days=0, hours=0, minutes=0, seconds=0):
    timedelta = datetime.timedelta(weeks=weeks,
                               days=days,
                               hours=hours,
                               minutes=minutes,
                               seconds=seconds)
    return (datetime.datetime.utcnow() + timedelta).isoformat()


def wait_until_valid(bdb, tx):
    for i in range(5):
        try:
            if bdb.transactions.status(tx['id']).get('status') == 'valid':
                return
        except bigchaindb_driver.exceptions.NotFoundError:
            pass
        time.sleep(1)

    raise bigchaindb_driver.exceptions.NotFoundError()


def retrieve_public_key_transaction(bdb, verify_key):

    unspents = map(lambda x: x['transaction_id'],
                   bdb.outputs.get(verify_key, spent=False))

    for txid in unspents:
        tx = bdb.transactions.retrieve(txid)
        asset = tx['asset'].get('data', {})
        if asset.get('op') == 'wot:publish':
            return tx


def retrieve_public_key(bdb, verify_key):
    tx = retrieve_public_key_transaction(bdb, verify_key)
    if tx:
        return tx['asset']['data'].get('public_key')
