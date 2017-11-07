# BigchainDB Sharing Tools (bst.py)

`bst.py` is a collection of utilities to share anonymous or encrypted payload
in BigchainDB.

It currenty implements the "Privacy + Queryability" scenario described in [1].


# Before we start
If you are going to use the command line interface remember to run a nice
`pip install -r requirements.txt`.

Remember also to set the URL of the BigchainDB API endpoint with `export
BIGCHAINDB_HOST <host>`.


# TL;DR
This is the sequence of commands to have **alberto** transfer a data point to
**bob** using the anonymize pattern. Read the following section to understand
what the commands do.

```bash
./bst.py create_keypair alberto
./bst.py -k alberto publish_key
./bst.py create_keypair bob
./bst.py -k bob publish_key
echo '{"type":"location", "lat":52.496594,"lon":13.4368584}' > location.json
./bst.py -k alberto anonymize location.json
# get the transaction id
./bst.py -k alberto transfer bob <txid>
./bst.py -k bob unspents_anon --show-asset
```

# Description

## Extending BigchainDB keypair to support encryption
BigchainDB supports Ed25519 signatures. Ed25519 is extremely interesting for
its speed in generating a keypair, signing payloads, verifying signatures, high
security, and [much more](https://ed25519.cr.yp.to/).

Even if it cannot be used for public-key encryption, a private signing-key can
be used to generate a new keypair to support encryption. This is pretty
interesting, because we can support encryption directly using a BigchainDB
keypair.

To generate a keypair run:
```bash
$ ./bst.py create_keypair
```

This will generate a keypair and store the seed under `.${USER}.bcdb_seed`.
To generate keypairs for multiple actors, run:
```bash
$ ./bst.py create_keypair <name>
```

To display your keys run:

```bash
$ ./bst.py keys

*** PUBLIC KEYS ***
verify  A924zbNr4VtpoTvECEPTjwefNboiDF6fUoYzJNN59JDW
public  7mu5Y5ik9LneUJ87rAjXp2qY1N8rVzdJeuxLrb1hnFpz

*** PRIVATE KEYS ***
sign    7rXJ64ChuNHcjUGM4ME3jKq5K7eJJnrR894eNpEVT7B2
private 3jRcVkpQPJTcJidCwjppXhWEeokomGgVkr7ahYkB4Tzt
```

To clarify, those are the keys involved:
 - `verify key`: Ed25519 public key used only to verify a signature
 - `sign key`: Ed25519 private key used only to sign a payload
 - `public key`: Curve25519 public key used to encrypt a payload
 - `private key`: Curve25519 private key used to decrypt a cipher


## Publish your `public key`
Since it is not possible to derive a `public key` from a `verify key`, we need
to publish it.

To do so, run:
```bash
$ ./bst.py publish_key
84ef7d7d5fe10cf4694961192e67527963876fe1273c0352096dc415f378a2bc
```

The return value is the `txid` of the transaction.

Let's take a look to the content:

```bash
./bst.py tx 84ef7d7d5fe10cf4694961192e67527963876fe1273c0352096dc415f378a2bc
{
  "asset": {
    "data": {
      "dt": "2017-03-21T13:21:33.201511",
      "op": "wot:publish",
      "public_key": "7mu5Y5ik9LneUJ87rAjXp2qY1N8rVzdJeuxLrb1hnFpz"
    }
  },
  "id": "84ef7d7d5fe10cf4694961192e67527963876fe1273c0352096dc415f378a2bc",
  "inputs": [
    {
      "fulfillment": "cf:4:h8cJkCpCl7C3XhKVXBymono0tw3jis9xZW_oZ4fTkpkbjo2xpXzRgnOjCxQUgIOTkzozPgwG1ipqutxigrGYMqvTdsxZRoyhJaJoKwX18AbQyD4T-q112QRFxlPHnCsC",
      "fulfills": null,
      "owners_before": [
        "A924zbNr4VtpoTvECEPTjwefNboiDF6fUoYzJNN59JDW"
      ]
    }
  ],
  "metadata": null,
  "operation": "CREATE",
  "outputs": [
    {
      "amount": 1,
      "condition": {
        "details": {
          "bitmask": 32,
          "public_key": "A924zbNr4VtpoTvECEPTjwefNboiDF6fUoYzJNN59JDW",
          "signature": null,
          "type": "fulfillment",
          "type_id": 4
        },
        "uri": "cc:4:20:h8cJkCpCl7C3XhKVXBymono0tw3jis9xZW_oZ4fTkpk:96"
      },
      "public_keys": [
        "A924zbNr4VtpoTvECEPTjwefNboiDF6fUoYzJNN59JDW"
      ]
    }
  ],
  "version": "0.9"
}
```

Since:
- the signature includes `tx['asset']`
- the transaction is signed by `tx['inputs'][0]['owners_before'][0]`
- the signature is included in `tx['inputs'][0]['fulfillment']`

We can assert that `A924zbNr4VtpoTvECEPTjwefNboiDF6fUoYzJNN59JDW` owns
`7mu5Y5ik9LneUJ87rAjXp2qY1N8rVzdJeuxLrb1hnFpz`.


## Publish anonymized data
This protocol follows [1], *Privacy + Queryability* section.

Data is published in cleartext using a common keypair that **anyone** can generate.

To publish a `json` payload using the cli, run:

```bash
$ ./bst.py anonymize <json-file>
d052b5e299e98ad14f02ce3ea27dfdc617e8964a195029cc8b6a38c170e4869a aC1CKZWF2mTBiDa7Yzzlnpw41XLwbieaRaq8CzrF9sU=u
```

Note that this command returns a **transaction id** and a **proof**. To understand what the **proof** is for,
we need to take a look to the transaction:

```bash
$ ./bst.py tx d052b5e299e98ad14f02ce3ea27dfdc617e8964a195029cc8b6a38c170e4869a
{
  "asset": {
    "data": {
      "lat": 52.496594,
      "lon": 13.4368584,
      "op": "anon:create",
      "proof_hash": "6e94ec9da3c5b81ffe63ef594f1b9ba9bd24491d3ed074840530290e262917a6",
      "ts": "2017-03-21T15:46:43.918985",
      "type": "location"
    }
  },
  "id": "d052b5e299e98ad14f02ce3ea27dfdc617e8964a195029cc8b6a38c170e4869a",
  "inputs": [
    {
      "fulfillment": "cf:4:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1xtSOfb6IY6U0b0hHmuMfTJVWu2MmBk-0LhWbC6QFhjf8YJZFW2LgZoGebSSv0KxjLTPL2Aun6XL5WBcSZpsUQP",
      "fulfills": null,
      "owners_before": [
        "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"
      ]
    }
  ],
  "metadata": null,
  "operation": "CREATE",
  "outputs": [
    {
      "amount": 1,
      "condition": {
        "details": {
          "bitmask": 32,
          "public_key": "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9",
          "signature": null,
          "type": "fulfillment",
          "type_id": 4
        },
        "uri": "cc:4:20:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w:96"
      },
      "public_keys": [
        "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"
      ]
    }
  ],
  "version": "0.9"
}
```

Remember, this transaction has been created by a shared keypair that anyone can
use. The anonymous keypair is generated using a simple seed (specifically,
`0x01 × 32`) hence anyone can generate the **signing key** and **verify key**.

`proof_hash` is the has of **proof**, and it can be eventually used to reveal
who is the creator of the transaction. Note that **proof** is stored by the
user together with the `txid`.


## Transferring anonymized data
Let's say a user wants to reveal their identity to a third party.

```bash
$ ./bst.py transfer alice fe88b3d14d21406e725b4c5c5cbd721a41f17be2a5462d16cdb436c4cc7d6681
f72c62f9c420e5fb1d7250b2087d8fbbb499b40797c3a263a05a51e92664ad08
```

This command will generate two transactions.

### Create Transaction
The first step is to create a transaction containing `[(txid0, P0), (txid1, P1), …, (txidn, Pn)]`,
encrypt it with a symmetric key, and then encrypt `key` using Alice's **public key**.

```bash
./bst.py asset b9ab27c733f74b53e806350a310f6670273cdb8f08681de6764352f4d325e0b0
{
  "cipher": "+ln8hJlG9sV2FiT8fnaMYDpHYJOjSnjD/uuk5V6O3jshhHls8MY++Ddij0APPLDS8uLMf2l1du4Gx2y57Ax3bjsgnJx\
             Ue9W+9+vvRNhOHpew/B9raJCGuhL4k8lFeNalSwq6HT+C5HGPwW5CDA+lv+lrRH0U6wcbPqBbmwA20Y6wJHl73/GH04\
             3c8i+GcUKWy9/6R1aioBgUJ/cJxe7EXHpjdhBwq9AU+1HaiGkKPU9FZbW02ZHUWv+kvOQeeXiS34gTbvfEF/eTvU72j\
             esaBy635GObB+BGQkgKbX1mnQ6MxqkM7DR3V6ib4hZYY9E/K9hIhqqBRyiVR2yGCgFbKQ==",
  "key": "QivAm+s53iePVmY5wMiPYE/OxSsd4Xg5wDkZKQLXfCUy4PkpTHxtY9oMbOLA46k5YI3QP7wDvp55SyJlWpDbmY7jeXjfFrX1",
  "op": "anon:transfer"
}
```

### Transfer Transaction to `alice`
The second step of this "anonymous transfer" is to transfer to Alice the
encrypted transactions and proofs.


## Reading anonymized data
Alice can now retrieve her unspents.

**Note**: this time `bst.py` is called with the `--keypair` option to use a
different keypair than the standard one.

```bash
./bst.py --keypair alice unspents_anon --show-asset
03f0bceb576c888268a749108ff0a1907d721d83d2b0691b9076cfb42b3d07d8
{
  "transactions": [
    [
      "fe88b3d14d21406e725b4c5c5cbd721a41f17be2a5462d16cdb436c4cc7d6681",
      "+MSmQv8dy0X1Vz18fEFv0vfEsNJU5higkPNVLrOjfro="
    ]
  ],
  "valid_from": "2017-03-21T14:03:57.901820",
  "valid_to": "2017-04-04T14:03:57.901879"
}
```

Alice now can connect the data from
`fe88b3d14d21406e725b4c5c5cbd721a41f17be2a5462d16cdb436c4cc7d6681` to the
identity that issued the transfer.



# Links
[1]: https://docs.google.com/document/d/1j2xFd7q075XXFu7ti-e4lwp9mJ3mPJAkNpyswWxToJ4/edit
