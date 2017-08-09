*:dragon: Here be Dragons: this document is a **work in progress**. If you have any feedback feel free to open an issue or a pull request. :dragon:*


# Sharing private data in a public blockchain
This paper specifies a standard to enable sharing of private information on a public blockchain.


## Rationale

Blockchains are evolving from managing tokens of value to handling digital assets and securely executing business logic. [BigchainDB][bigchaindb] is a prime example of this evolution in the area of digital assets.

Storing and sharing digital assets raises new hard privacy challenges, e.g. most of the people do not want to share their health records or their land property documents with the world, and interesting regulatory challenges, e.g. how can regulators reconcile the necessary transparency to improve trust in the financial system while ensuring data privacy where it is warranted.

Privacy is a vast subject, and its interpretation depends heavily on the context. In some cases **privacy** means keeping an asset **encrypted** and readable only for designated users. Other times **privacy** means **anonymity**, for example when WikiLeaks publishes classified information keeping sources anonymous.

This paper focuses on exploring the questions of secure and private data sharing between one or more counterparties.


## Disclaimer
This paper compares how different cryptocurrencies handle transactions confidentiality. The focus is on how **information** is stored in the transaction itself, not on mining, block ordering, block chaining, nor how a decentralized network is Byzantine fault tolerant.

The cryptocurrencies featured in this paper are:

- **Bitcoin**, for its wide adoption and historical importance.
- **Ethereum**, for its innovative approach as a distributed computing platform.
- **Monero**, for the focus on privacy and untraceability.
- **Zcash**, for using a zero-knowledge proof crypto protocol.


# Introduction
Confidentiality and privacy for blockchains is not a new topic; above all, the extensive [R3 report][r3:report] gives a great overview of the current status for privacy and confidentiality in the blockchain space. The following paragraph, taken from the introduction of the report, frames quite well the intent of this document.

> In the early days of the Web, the Secure HyperText Transfer (HTTPS) and Secure Sockets Layer (SSL) protocols emerged as competing standards for adding privacy to the Web, with SSL eventually triumphing. We expect blockchain technology to follow a similar path, with multiple competing privacy standards emerging over the next few years.

Transparency and verifiability are key features of blockchains. Those key features are used by the blockchain consensus itself, to balance off accounts. A blockchain—in order to avoid double spends—should be able to verify that an account has enough balance to satisfy the transaction towards another account.

The logic behind a specific cryptocurrency **must** be able to extract some information from the transaction in order to decide if the transaction is valid or not. This brings us to an important (and quite obvious) conclusion:

> An asset, in order to be a first-class citizen in a blockchain system, must allow computability.

This is as obvious as it is important: if we want to automate and delegate the management of assets to a decentralized system, the system itself should be programmed in a way to understand those assets.


## On asset types, verifiability, and confidentiality
This report uses the same definition of **confidentiality** that R3 uses, specifically:

> [...] we use the term confidentiality in the context of protecting data (e.g. transaction details, price, asset types, account and wallet balances, the business logic of smart contracts) from unauthorised third parties.

We can identify three different properties associated with an asset, specifically:

- **Type**: the nature of the information stored. It can be
    - *Scalar*, a number or a string.
    - *Text*, a paragraph of free text from a novel, or some source code. (Someone might argue this is a subset of *scalar*, but we mean something more like a text file). A human should usually be able to parse that.
    - *Structured*, information organized in a specific manner, e.g. a `JSON` document.
    - *Binary*, a blob of binary data, e.g. audio encoded in `mp3` format, a compressed archive, an image, or more. A human should not be able to parse that.
- **verifiability**: can the network itself interpret the asset and give a response on the asset validity?
- **confidentiality and verifiability**: can be framed as *the ability of an asset to still be verifiable while keeping confidentiality*. In other words: if the asset is encrypted, can a program still verify it?

Starting from the **asset type**, let's see how different ledgers handle verifiability and confidentiality.


### Scalar assets
Bitcoin, Ethereum, Monero, and Zcash natively support *scalar quantities*. This is a requirement for every cryptocurrency: without it, scarcity cannot be achieved, and scarcity is a fundamental property of everything having monetary value. BigchainDB, even if it's not a cryptocurrency, handles scalar quantities as well.

For the Bitcoin and Ethereum network, all the exchanges of value are publicly readable. As an example, anyone can easily check how many bitcoins [XKCD received][xkcd-donations] to his [personal wallet][xkcd-wallet] from donations.
BigchainDB allows to [specify an amount][bigchaindb:amount] on asset creation.

On the other side, other cryptocurrencies like [Zcash][zcash:tech] and [Monero][monero:overview] preserve transaction confidentiality adding a new layer of privacy for the users. Zcash achieves this by using a zero-knowledge cryptography protocol called [zkSNARK][zcash:zksnark]. Monero uses a combination of [stealth addresses][monero:stealth] and [ring signatures][monero:ring].

For every technology listed, *scalar quantities* are **verifiable**, but only for Zcash and Monero **confidentiality and verifiability** of the transaction is maintained.

### Text assets
Bitcoin does not natively support extra text data, but [hacks are possible][bitcoin:text-asset]. Protocols have been built on top of the Bitcoin `OP_RETURN`, the [SPOOL Protocol][spool] is a prime example of that.

Monero [payment ID][monero:payment-id] is an optional 32 bytes field that can be used to store additional information on a payment.

Zcash [memo field][zcash:memo-field] allows to attach an optional 512 bytes message to a transaction.

BigchainDB allows arbitrary `JSON` payloads, so strictly speaking *text only assets* are not allowed.

Those four technologies don't allow for **verifiability** for text assets, in other words the network cannot approve or reject transactions based on their text content. Protocols built using text assets must rely on an overlay network to add a new layer of validation.

Ethereum allows to attach a [payload of arbitrary size][ethereum:send-transaction] to the transaction. The payload can be interpreted as a byte string. The bigger the transaction is, the more gas is needed for the network to process it. (The payload is also used to initialize smart contracts.)

Related to **verifiability**, a modified Ethereum [ERC20][ethereum:erc20] token may add a text field to the token itself. The field would then be processed by the smart contract itself and used to accept or reject transactions. This approach is in a way similar to the *overlay protocol* explained before, with the benefit that the execution of the protocol would live in the network itself, hence being be *decentralized*.

Let's spend some more words on the concept of **verifiability** of a *text asset*. A program, in order to discern valid transactions from invalid transactions, must be able to parse the text input. Even if an Ethereum smart contract can run and process arbitrary text, the text that has been tested for validity must be interpretable by the program itself.

In an Ethereum smart contract, **confidentiality and verifiability** might be allowed as well depending on the nature of the text asset (*can we run zero knowledge proof protocols on it?*). Since smart contracts are Turing complete, the assumption is that a smart contract with enough gas can execute zero knowledge proof algorithms.

### JSON (or structured) assets
Bitcoin has shown that arbitrary text can be stored. Since `JSON` is a subset of a generic text, everything we said in the previous section is still valid.

Considering the limited space in Monero `payment ID`, a `JSON` object is too large to be stored.

BigchainDB is able to store native `JSON` structures, and everything that has been said for Bitcoins in the previous section applies.

Ethereum can store arbitrary text, and everything that has been said in the previous section applies.

### Binary assets
A binary blob can be encoded as text using different encodings. Everything said in the previous section applies.

Please keep in mind that storing binary data in a blockchain is inefficient and expensive.

(Fun fact: someone stored the iconic sentence *I'm sorry Dave, I'm afraid I can't do that* as an [audio file][ethereum:audio-file] in Ethereum.)


# On verifiability and confidentiality
The previous section explained how **verifiability and confidentiality** can be achieved using scalar quantities. In case of different asset types, custom algorithms must be developed, but with a warning: adding **verifiability** to a confidential asset can be a hard problem to solve. Let's see some examples.


#### A blockchain for Linked Data
Let's say we want to store linked data in a blockchain, using the [JSON-LD][jsonld] format. JSON-LD `@context` and `@type` are used to enforce the schema of the data. Given a property, its [domain][rdf:domain] and [range][rdf:range] can be used to validate the semantics of the data itself.

Schema validation is a first step, we can climb up the semantic web ladder and add more and more validation rules.

![Semantic Web stack][image:semantic-web-stack]
*The [Semantic Web Stack][rdf:semantic-web-stack]*

Let's stick for a second with the simple case: schema validation. A transaction is considered valid if and only if it passes validation. In this case, **verifiability** is easy to implement, and the validation is generic enough to be used for any kind of `JSON-LD` document.

Combining **confidentiality and verifiability** would mean to let users exchange valid **and** encrypted transactions between them. This would require the creation of a new (eventually) *non-interactive*, zero-knowledge proof protocol that would allow validation nodes in the network to decide on the validity of the transaction.


#### A blockchain for cat images
Let's spice up our blockchain with some AI. The validation rule for this blockchain is quite simple: a transaction, to be considered valid, must contain a picture of one or more cats. As we already said, storing binary data in a transaction is not efficient: for this use case a transaction will contain a pointer to a content-addressable picture (stored in [IPFS][ipfs], for example).

<!--![Picture of Parker Posey, professional cat][image:parker-posey]-->

Given an image, a *cat classifier* returns the probability that the image contains a cat. Absolute certainty on the presence of a cat is not achievable, so let's assume that if the confidence is greater than `0.99` then the transaction is valid. This makes the transaction **verifiable**.

Combining **confidentiality and verifiability** would imply to run a classifier on encrypted data. [Breakthrough encryption techniques][numerai] might enable this, but it's still a field under active research and development.


# Sharing encrypted assets
In this section we analyze how an exchange of encrypted asset is initiated, managed, and what are its properties.


## Properties of the system
The system described in this paper wants to provide several guarantees for the end users, specifically:

- Proof of Sharing
- Authentication
- Data integrity
- End to end encryption
- Perfect forward secrecy


### Proof of Sharing
BigchainDB is a general purpose blockchain database, and does not constrain users to any specific kind of (`JSON`) assets. Therefore, a generic approach is preferred. From our knowledge, there is no crypto system that can guarantee both **verifiability and confidentiality** of generic asset. **Confidentiality** is still achievable by classic encryption protocols. But if we drop **verifiability** how do we make sure players in the will system cooperate?

Introducing **Proof of Sharing**. Proof of Sharing is an optimistic approach that allows cooperating actors to have frictionless and secure exchange of data. Let's say *Alice* wants to access some private data owned by *Bob*. The interaction between them is the following (technical details will be discussed throughout this paper):

- *Bob* owns the asset *X*. He publishes some metadata and **conditions** on how to get *X* (e.g. a simple case would to set the price of the asset).
- *Alice* wants to access and read *X*, she reads the metadata and conditions about *X*, and she makes a payment (or whatever is needed) using the required fiat or crypto currency.
- *Alice* transfers her access token (in this case, a payment receipt) for *X* to *Bob*.
- *Bob* verifies that the access token is valid, and starts a **handshake** to create a shared *session key* with *Alice*
- *Alice* participates to the **handshake**.
- Both *Alice* and *Bob* have now the same *session key*.
- *Bob* encrypts *X* using the previously calculated *session key* and share it (on-chain or off-chain) with *Alice*.

If both *Alice* and *Bob* played by the rules, everyone is happy and no conflict resolution is needed. But what happens when one of them acts maliciously? *Alice*, once she obtained the private asset *X*, can say it was not the asset she paid for, and ask for a refund. On the other side, *Bob* can transfer to *Alice* total garbage.

The important part is the **handshake** between *Alice* and *Bob*. Here the blockchain plays a crucial role. By storing all those steps as transactions in the system, *Alice* or *Bob* are able to expose malicious behaviour to a third party.

Alas, finding the culprit is not enough, especially when they are anonymous. To properly disincentivize malicious actors, a **stake** is added to the **handshake**. The stake can be kept secret between parties, and revealed when a conflict occurs. By using [crypto conditions][cc:draft] combinatory logic, *Alice* and *Bob* can create a threshold condition `n-of-m`, where `m` defines the third parties involved that can eventually release the funds to the injured party.

**Note: stake is not a requirement, but it adds another level of security. If the identity of the parties is known (i.e. KYC has been done correcty), then the litigation can be solved in other ways, by legal means for example.**


### Authentication
Authentication proves that a message came from a particular sender.

In case of symmetric encryption, this is usually achieved using a [(Hashed) Message Authentication Code][hmac]. For asymmetric encryption, a [digital signature][pki-signature] of the message is used.


### Data Integrity
Data Integrity makes sure that tampered messages are detectable.
TK: elaborate more

### End to End encryption
TK: finish this section

### Perfect Forward Secrecy
[Perfect forward secrecy][pfs] is a property of secure communication protocols in which compromise of long-term keys does not compromise past session keys. Forward secrecy protects past sessions against future compromises of secret keys or passwords. If forward secrecy is used, encrypted communications and sessions recorded in the past cannot be retrieved and decrypted should long-term secret keys or passwords be compromised in the future, even if the adversary actively interfered.

This property is crucial in a blockchain use-case: since all data is stored forever, if a key is leaked it can compromise a significant amount of assets. Also, *proof of sharing* might require to reveal keys when dealing with a malicious actor.


# The Transport Layer Security Protocol
Instead of creating a new protocol from scratch, we decided to stand on the shoulders of a widely used, reviewed, industry ready standard: the [**Transport Layer Security 1.2**][tls:rfc5246] (TLS henceforth) protocol. (Version 1.3 is currently in development, we might upgrade this paper once it's ready.)
TLS is used to provide communications security over a computer network; for example, when a browser connects to a website using `HTTPS`, the session key used for the symmetric encryption is established using a combination of protocols defined by TLS. The process of establishing a secure connection is called **handshake**, and it's done in *real time* between the client and the server. Even if TLS is perceived as a "low latency" protocol (the handshake takes few hundreds of milliseconds), we argue that it can be used in a higher latency scenario, that is the blockchain one. This section explains which parts of TLS are suitable to help us fulfilling the properties described before.


## TLS Handshake
TK: is it ok if I copy paste https://en.wikipedia.org/wiki/Transport\_Layer\_Security#TLS\_handshake ?
![TLS Handshake, https://upload.wikimedia.org/wikipedia/commons/thumb/d/d3/Full\_TLS\_1.2\_Handshake.svg/2000px-Full\_TLS\_1.2\_Handshake.svg.png][image:tls-handshake]

## TLS Cipher Suites
TLS defines a large number of [*Cipher Suites*][tls:cipher-suites]. A *cipher suite* is a named combination of authentication, encryption, message authentication code, and key exchange algorithms used to negotiate the security settings.

If you have `openssl` installed in your machine, it's fairly easy to have a list of the *cipher suites* available:
```bash
$ openssl ciphers -v -tls1
DH-RSA-AES256-SHA256      TLSv1.2 Kx=DH/RSA Au=DH    Enc=AES(256)  Mac=SHA256
ECDHE-ECDSA-AES256-SHA384 TLSv1.2 Kx=ECDH   Au=ECDSA Enc=AES(256)  Mac=SHA384
DH-RSA-AES256-SHA         SSLv3   Kx=DH/RSA Au=DH    Enc=AES(256)  Mac=SHA1
... 94 lines omitted ...
```

Each item on the list defines a combination of key exchange (`Kx`), authentication (`Au`), encryption (`Enc`), and message authentication (`Mac`).

Let's analyze the first line: `DH-RSA-AES256-SHA256`.

- **DH**: key exchange will use Diffie-Hellman
- **RSA**: authentication will use RSA for authentication
- **AES256**: data will encrypted using Advanced Encryption Standard, with a key length of 256 bits.
- **SHA256**: data integrity will be ensured by Secure Hash Algorithm 2, with a digest size of 256 bits.

As you can see, a *cipher suite* cover most of the properties we described before, specifically:

- Authentication
- End to end encryption
- Data integrity

What is still out of the equation is **Perfect forward secrecy**, but no worries, TLS provides a collection of **ephemeral** key exchange algorithms that fulfill this requirement. We can easily query for them:

```bash
$ openssl ciphers -v -tls1 | grep DHE
ECDHE-RSA-AES256-GCM-SHA384   TLSv1.2 Kx=ECDH Au=RSA   Enc=AESGCM(256) Mac=AEAD
ECDHE-ECDSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH Au=ECDSA Enc=AESGCM(256) Mac=AEAD
ECDHE-RSA-AES256-SHA384       TLSv1.2 Kx=ECDH Au=RSA   Enc=AES(256)    Mac=SHA384
ECDHE-ECDSA-AES256-SHA384     TLSv1.2 Kx=ECDH Au=ECDSA Enc=AES(256)    Mac=SHA384
ECDHE-RSA-AES256-SHA          SSLv3 Kx=ECDH   Au=RSA   Enc=AES(256)    Mac=SHA1
ECDHE-ECDSA-AES256-SHA        SSLv3 Kx=ECDH   Au=ECDSA Enc=AES(256)    Mac=SHA1
... 28 lines omitted ...
```

A key exchanged using an ephemeral protocol **must not** be stored for longer that the session itself.

Now that we have an overview on how TLS and cipher suite work, we can dig into details and describe how we can adapt TLS to suite our needs.


## On authentication
All transactions in a blockchain network are digitally signed with the public key(s) of the issuer(s), hence each message is authenticated per se. TLS has a set of cipher suites that allow us to disable authentication. In this case, if for the parties involved a signed message suffice, they can ignore extra certificates and move on.

### Extending support to X.509 certificates
Still, it might be useful for some use cases to enable `X.509` certificates. Most of the *old* web still relies on them, so why not use them?

## On symmetric encryption
Since 2008, Intel and AMD CPUs provide an extension to the x86 instruction set architecture called **Advanced Encryption Standard Instruction Set**.
For Intel, this feature has been added to commodity CPUs like **i5** and **i7**. Even if AES is the standard symmetric encryption algorithm for many use cases, it's worth notice that it performs extremely well on those specific CPUs. The `openssl` command can run a speed test on specific encryption algorithms. To taste the speed-up on your machine, you can run `openssl speed`.

On a Intel Core i5-2520M CPU, 2.50GHz, this is the result of the benchmark without and with the instruction set enabled.

```bash
$ openssl speed -elapsed aes-128-cbc
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes
aes-128 cbc      95411.96k   102425.79k   104104.19k   105198.25k   105502.04k


$ openssl speed -elapsed -evp aes-128-cbc
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes
aes-128-cbc     559001.23k   603807.10k   615512.66k   619206.31k   617106.09k
```

A normal CPU can provide a 6x increment in performance just by setting a flag, nice!


# Protocol Definition
Time to talk on how this works with a blockchain. The scenario is the one described before: *Alice* just spent some bitcoins to buy a digital asset *X* from *Bob*.

Ideally, Alice and Bob will pass the same transaction around, creating an audit trail of their handshake.


## Step 0: Bob publishes metadata about his payload
Bob has few private assets he is willing to share under certain conditions. For each asset, he creates a transaction and push it to the network. Those transactions contain metadata about the assets. We haven't defined yet a schema for metadata, but they will be expressive enough to cover those (and more) use cases:

- sell an asset for a fixed price
- give read permission to an asset for a time interval
- etc.

If needed, each payload offer can have an extra field with the stake that Bob puts to vouch the offer. This stake must be read as "if I'm not delivering what I promise, the stake is yours".

(A reputation system can be used, both as a complementary guarantee, or as an alternative to stake.)


## Step 1: Alice starts a negotiation with Bob.
Alice transfers a transaction to Bob. Bob has to reply to **know** what Alice wants and do actual work. This is of course susceptible to spam, so Alice puts stake to prove she is not spamming him. If there is a trust relationship between Alice and Bob, she might omit the stake.

The transaction contains a payload structured like:

```json
{
  "stake_id": "<reference to a no-spam stake she puts on the table>",
  "nonce": "<a sequence of 32 random bytes>",
  "ciphersuites": [
    "ECDHE-NULL-AES256-GCM-SHA384",
    "DHE-NULL-AES256-GCM-SHA384",
    "<and more ciphersuites that Alice can manage"
  ]
}
```

## Step 2: Bob starts the pre-master secret exchange
Bob, after verifying the validity of the transaction, and assuming that he finds a cipher suite that he can handle, proceeds with the key exchange re-transferring the transaction to Alice. There is no need to specify any session id, or add extra information to keep track of this key exchange: the trail is kept in the transaction history.

```json
{
  "nonce": "<a sequence of 32 random bytes>",
  "stake_id": "<reference to a stake he puts on the table>",
  "ciphersuite": "ECDHE-NULL-AES256-GCM-SHA384",
  "params": "<Elliptic-curve Diffie-Hellman parameters>"
}
```

## Step 3: Alice sends back her parameters and put her (optional) stake on the table
Alice now chooses her Diffie-Hellman parameters, calculate the pre-master secret, derives the session key, and sends the transaction back to Bob. She can now exchange **encrypted payloads** with Bob!

**Note: from now on, `cipher` contains the encrypted payload, encoded in Base64. For the sake of clarity, the examples contain the plaintext.**

If the asset is "pay and forget", Alice puts her stake on the table, and she specifies which asset she needs.

Or she can start a secure, confidential negotiation between Bob and her, sharing his terms with him. If Bob find those terms acceptable, he will share the actual payload with Alice, otherwise he won't, and the negotiation will continue until both parties are satisfied.

```json
{
  "params": "<Elliptic-curve Diffie-Hellman parameters>",
  "cipher": {
    "asset_id": "<the ID of the asset she wants to obtain>",
    "stake_id": "<the actual stake she will lose if she reveals the payload>"
  }
}
```

## Step 4: Bob put his (optional) stake on the table
This step can be skipped if stake is not involved.

```json
{
  "cipher": {
    "stake_id": "<the actual stake she will lose if she reveals the payload>"
  }
}
```

## Step 5: Alice shares her receipt id with Bob
Alice can now reveal her access token. If Bob doesn't fulfill her request, she can reveal the pre-master key and get Bob's stake.

```json
{
  "cipher": {
    "access_token": "<reference to the access token (can be a bitcoin tx)>",
  }
}
```

## Step 6: Bob shares his asset
Bob can finally verify the access token and share his secret with Alice. Alice has one week of time to verify the validity of the asset. In this week, if Bob uploaded the asset off-chain, the asset must be retrievable for one week. This will allow audits from third parties in case of litigation.

## Channels
Alice and Bob had actually created an encrypted, secure channel on the blockchain, that they can reuse in the future. They might need to refresh keys once in a while, but this topic is out of the scope of the current document.


# Conclusion
Ensuring privacy in a public blockchain is not a trivial task. Leveraging well tested technologies like TLS can help us reaching the level of confidentiality we need in order to unlock new use cases for blockchain technology.

The paper described here is a first attempt towards that.




# Other resources:
Some other interesting links on the topic:
- https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/
- https://crypto.stackexchange.com/questions/3965/what-is-the-main-difference-between-a-key-an-iv-and-a-nonce
- https://askubuntu.com/questions/60712/how-do-i-quickly-encrypt-a-file-with-aes
- https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
- https://crypto.stackexchange.com/questions/18538/aes256-cbc-vs-aes256-ctr-in-ssh
- https://security.stackexchange.com/questions/81597/in-psk-tls-how-is-the-key-used-for-encryption-derived
- https://en.wikipedia.org/wiki/Key_stretching
- https://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac
- https://blog.cryptographyengineering.com/2012/05/19/how-to-choose-authenticated-encryption/
- http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm
- http://www.thesprawl.org/research/tls-and-ssl-cipher-suites/
- https://moxie.org/blog/the-cryptographic-doom-principle/
- http://www.iacr.org/cryptodb/archive/2003/EUROCRYPT/2850/2850.pdf
- https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki "Hierarchical Deterministic Wallets"
- https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki "Multi-Account Hierarchy for Deterministic Wallets"
- https://bitcoin.org/en/developer-guide#hierarchical-deterministic-key-creation "Hierarchical Deterministic Key Creation"
- https://sevdev.hu/ipns/sevdev.hu/posts/2016-11-16-working-with-bitcoin-hd-wallets.html "Working with Bitcoin HD wallets: Key derivation"
- https://medium.com/@sevcsik/working-with-bitcoin-hd-wallets-ii-deriving-public-keys-c48341629388 "Working with Bitcoin HD wallets II: Deriving public keys"
- https://vincent.bernat.im/en/blog/2011-ssl-perfect-forward-secrecy
- https://bitcointalk.org/index.php?topic=19137.msg239768#msg239768
- https://cr.yp.to/ecdh/curve25519-20060209.pdf
- http://www-cs-students.stanford.edu/~tjw/jsbn/ecdh.html
- https://cr.yp.to/ecdh/curve25519-20060209.pdf
- https://safecurves.cr.yp.to/
- https://tools.ietf.org/html/rfc4492
- https://github.com/ethereum/devp2p/blob/master/rlpx.md#encrypted-handshake
- https://github.com/indutny/elliptic
- https://hpbn.co/transport-layer-security-tls/
- https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
- https://github.com/openssl/openssl/issues/309#issuecomment-216517132

<!-- References -->
[r3:report]: https://z.cash/blog/r3-blockchain-report.html
[bigchaindb]: https://www.github.com/bigchaindb/bigchaindb/
[bigchaindb:amount]: https://docs.bigchaindb.com/projects/server/en/v1.0.1/data-models/inputs-outputs.html
[hmac]: https://en.wikipedia.org/wiki/Hash-based\_message\_authentication\_code
[pki-signature]: https://en.wikipedia.org/wiki/Public-key\_cryptography#Digital\_signatures
[pfs]: https://en.wikipedia.org/wiki/Forward\_secrecy
[xkcd-donations]: https://blockchain.info/address/14Tr4HaKkKuC1Lmpr2YMAuYVZRWqAdRTcr
[xkcd-wallet]: https://xkcd.com/bitcoin/
[monero:overview]: https://getmonero.org/get-started/what-is-monero/
[zcash:tech]: https://z.cash/technology/
[zcash:zksnark]: https://z.cash/technology/zksnarks.html
[monero:stealth]: https://getmonero.org/resources/moneropedia/stealthaddress.html
[monero:ring]: https://getmonero.org/resources/moneropedia/ringsignatures.html
[bitcoin:text-asset]: http://www.righto.com/2014/02/ascii-bernanke-wikileaks-photographs.html
[ethereum:send-transaction]: https://github.com/ethereum/wiki/wiki/JavaScript-API#web3ethsendtransaction
[monero:payment-id]: https://getmonero.org/resources/moneropedia/paymentid.html
[spool]: https://github.com/ascribe/spool
[zcash:memo-field]: https://z.cash/blog/encrypted-memo-field.html
[ethereum:erc20]: https://theethereum.wiki/w/index.php/ERC20_Token_Standard
[ethereum:audio-file]: https://www.reddit.com/r/ethereum/comments/3hx73f/freakiest_thing_ever_the_blockchain_now_has_a/
[jsonld]: https://json-ld.org/
[rdf:domain]: https://www.w3.org/TR/rdf-schema/#ch_domain
[rdf:range]: https://www.w3.org/TR/rdf-schema/#ch_range
[image:semantic-web-stack]: ./images/semantic-web-stack.png
[rdf:semantic-web-stack]: https://www.w3.org/RDF/Metalog/docs/sw-easy
[ipfs]: https://ipfs.io/
[image:parker-posey]: ./images/parker-posey.jpg
[numerai]: https://medium.com/numerai/encrypted-data-for-efficient-markets-fffbe9743ba8
[cc:draft]: https://tools.ietf.org/html/draft-thomas-crypto-conditions
[tls:rfc5246]: https://tools.ietf.org/html/rfc5246 "The Transport Layer Security (TLS) Protocol Version 1.2"
[tls:cipher-suites]: https://tools.ietf.org/html/rfc5246#appendix-A.5
[image:tls-handshake]: ./images/tls-handshake.png


# Contributors
Contributors to this document, in alphabetical order:

- Alberto Granzotto <alberto@bigchaindb.com>



# RANDOM NOTES, IGNORE PLS
Solicited (pull) vs unsolicited (push) sharing.

## Protocol

- Alice --C{[proof], AlicePk, protocol=ECDHv1}--> Bob
- Bob --T{BobPk}--> Alice
- Alice --T enc{assetId, timeInterval}--> Bob
- Bob --T enc{uri, hash}--> Alice

Bob can cheat and:
 - ignore Alice's request: Alice can show the proof details to a third party
 - not upload the file: Alice can ask a third party to check the URI
 - upload another file: the hash won't match the file
 - upload a file matching the hash but with other content: Alice will reveal
   the session key to a third party that will verify the content
Alice cannot cheat: Bob can reveal the session key to a third party and prove
he was not cheating.

Alice can ask Bob for other assets by doing:
- Alice --T enc{assetId, timeInterval, proof}--> Bob
where the new parameter `proof` is the "receipt" that Alice "paid" for
`assetId`.


# Anonymous sharing
- Bob publishes his public key
- Anon --C{data, hash(secret), timeInterval}--> Bob
- Bob queries BigchainDB and selects the data he wants to read
- Anon --C{enc(BobPk, AlicePk, sign(AlicePk, secret))}--> Bob


### Proof [optional]

### Handshake


# Cryptographic protocols

## Without verifiability

### TLS-like

### Encryption proxy

### Shared secret

## With verifiability

### Zero-knowledge proof

### Homomorphic encryption
