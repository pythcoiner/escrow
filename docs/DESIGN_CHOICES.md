## Escrow

This project is an experimental Bitcoin 'Wallet' built around a peer-to-peer escrow contract
using Miniscript & Taproot.

## Abstract

The idea is to have a Bitcoin wallet with the following properties:
 - Single purpose: only aims to interact with escrow contracts.
 - Self-custody: you (and nobody else) own your cryptographic secrets.
 - Trustless: the escrow contract does not rely on any 3rd party acknowledging the contract; they are optional
   and are meant to interact only in last-resort or recovery cases.
 - Peer-to-peer: the contract is not 'hosted' nor 'executed' by a central coordinator. Middle parties 
   (like a Nostr relay) can be used as a transport: they carry an encrypted data package but do not know
   about the payload.
 - Secured by Bitcoin (Mini)script.
 - Uses Taproot & hashlocks.

The contract is the data representing the terms of a deal to be executed, including but not limited to:
 - Cryptographic identities of participants (Seller, Buyer, 3rd parties)
 - Amount to be paid.
 - Optional deposits that can be spent directly by the seller before contract execution.
 - Textual description of the terms (can also include a hash of attached documents).
 - Anything that can be represented as string(s) or byte(s).

## Motivation

Traditional escrow services rely on centralized third parties. By using Bitcoin's scripting capabilities, 
especially Miniscript and Taproot, this solution ensures self-custody and trustless transactions, eliminating 
the need for intermediaries.

The peer-to-peer architecture means the contract is not dependent on any central coordinator, enhancing privacy 
and security. By leveraging hashlocks and Taproot, the project offers efficient and flexible transaction structures. 

## Contract steps

The contract lifetime is composed of several steps:
 - Offered: The seller offers a contract after preliminary negotiation.
 - Refused: The buyer can refuse the contract terms, in order to renegotiate or cancel the contract.
 - Accepted: The buyer has accepted the terms of the contract.
 - Funded: The buyer has broadcasted an (or several) UTXO(s) matching the contract total amount, but
   the block confirmation target has not yet been reached.
 - Locked: Funded + blocks confirmation target has been reached.
 - Unlocked: The seller can now spend UTXO(s) without the buyer's consent.
 - Disputed: Buyer and seller do not agree on the issue of contract execution, coins are locked in
   the contract until they find an agreement or third-party action and/or timelock elapsed.

The contract lifetime can be represented by this chart: 

```
        ┌───────────┐        ┌───────────┐
        │  Offered  │◄───────│  Refused  │
        └───────────┘        └───────────┘
          │        │                  ▲
     buyer accepts └─ buyer refuses ──┘
          │
          ▼
        ┌───────────┐
        │ Accepted  │
        └───────────┘
              │
  buyer broadcasts funding tx
              │
              ▼
        ┌───────────┐
        │  Funded   │
        └───────────┘
              │
 utxo reaches <target> confirmations
              │
              ▼
        ┌───────────┐
        │  Locked   │
        └───────────┘
              │
     (contract execution) 
              │
              ├───────────────┐
              │               │
          agreement     no agreement
              │               │
              ▼               ▼
        ┌───────────┐   ┌────────────┐
        │ Unlocked  │   │  Disputed  │
        └───────────┘   └────────────┘
              │               │
              ▼               │
      Seller can spend        ├────────────────────────┐
                              │                        │
                              ▼                        ▼
                        timelock elapse           3rd party takes
                                                      action
```

## Identities

Identities of the contract participants are materialized by a key pair that permit:
 - Message signature, in our case signing states of the contract.
 - Message encryption.
 - Authentication.
 - Hashlock secret generation.

This implementation uses secp256k1 keys and messaging transport over the Nostr protocol.
Contract data is dumped as a JSON 'payload' and actually 'wrapped' into a Nostr NIP05 "Encrypted Direct Messages",
we should switch in the future to NIP17 "Private Direct Messages".

### XPubs/Derivation paths

For privacy & security reasons, we should not produce contracts with duplicate signing keys. Some signing devices 
have known limitations in their design, such as a maximum derivation depth of 8.

 - BIP388 restricts the XPub derivation path to `<multipath>/*` (depth of 2).
 - Our contract hash is a 32-byte array ([u8:32]) that we can convert into an 8 u32 array ([u32;8]).
 - Given this context, we opt for an XPub origin derivation path of depth 6 + a depth 2 for the XPub derivation path.
 - Contracts typically produce a single receive address, so static child numbers are used instead of multipaths and wildcards.

Special case of 3rd parties:

Third parties are kept unaware of contract details unless a dispute arises. These parties provide a single public XPub. 
Due to BIP 388 limitations, the entropy for this XPub derivation path is 2 bytes, as it is limited to 2 levels.
Non-hardened derivation paths are used to maintain compatibility with hardware signing devices. The maximum value 
for an unhardened derivation path is 2^31-1, meaning each byte from the contract hash provides 7 bits of entropy.

## Contract fields

```
|------------------|-------------------|-------------------------------------------------------------------|
|       Field      |        Type       | Description                                                       |
|:----------------:|:-----------------:|:------------------------------------------------------------------|
|      version     |        u32        | Version of the contract structure                                 |
|------------------|-------------------|-------------------------------------------------------------------|
|        id        |      [u8;32]      | The contract ID is a sha256 hash of the contract datastructure    |
|------------------|-------------------|-------------------------------------------------------------------|
|  contract_state  |         u8        | The contract's current state:                                     |
|                  |                   | - Empty                                                           |
|                  |                   | - Offered (seller pre-fills and signs this state)                 |
|                  |                   | - Accepted (buyer fills and signs this state)                     |
|                  |                   | - Refused (buyer updates and signs contract if he asks for        |
|                  |                   |   changes)                                                        |
|                  |                   | - Funded (Unconfirmed payment)                                    |
|                  |                   | - Locked (Confirmed payment)                                      |
|                  |                   | - Unlocked (Buyer shares hash with seller)                        |
|------------------|-------------------|-------------------------------------------------------------------|
|   contract_type  |         u8        | The contract can be of several kinds:                             |
|                  |                   | - Peer to peer                                                    |
|                  |                   | - Peer to peer with timelock                                      |
|                  |                   | - Peer to peer with escrow(s)                                     |
|                  |                   | - Peer to peer with escrow(s) & timelock                          |
|                  |                   | - ....                                                            |
|------------------|-------------------|-------------------------------------------------------------------|
|   total_amount   |        i64        | The total Bitcoin amount of the contract (in sats)                |
|------------------|-------------------|-------------------------------------------------------------------|
|      deposit     |        i64        | Amount of deposit (optional)                                      |
|------------------|-------------------|-------------------------------------------------------------------|
|     timelock     |        u32        | Timelock of the contract in Bitcoin blocks (optional)             |
|------------------|-------------------|-------------------------------------------------------------------|
|      details     |       string      | A text describing the contract between parties                    |
|------------------|-------------------|-------------------------------------------------------------------|
|       buyer      |      pub_key      | Buyer (Nostr) public key                                          |
|------------------|-------------------|-------------------------------------------------------------------|
|      seller      |      pub_key      | Seller (Nostr) public key                                         |
|------------------|-------------------|-------------------------------------------------------------------|
|   third_parties  | [(pub_key, xpub)] | A list of third parties that can interact as escrow(s) in case of |
|                  |                   | dispute. (optional)                                               |
|------------------|-------------------|-------------------------------------------------------------------|
|  buyer_signature |                   | See [buyer signature details](#buyer-signature)                   |
|------------------|-------------------|-------------------------------------------------------------------|
| seller_signature |                   | See [seller signature details](#seller-signature)                 |
|------------------|-------------------|-------------------------------------------------------------------|
|  contract_policy |                   | The Miniscript policy representing the contract spending          |
|                  |                   | conditions, see [policy section](#contract-policy)                |
|------------------|-------------------|-------------------------------------------------------------------|
```

## Communication Flow in case both parties agree on contract issue:

```
Seller                                                Buyer               Bitcoin Network
    |                                                     |                       |
    |   Pre-fill contract                                 |                       |
    |  ( Add Seller Xpub )                                |                       |
    | -------------- Send contract offer ---------------> |                       |
    |                                                     |                       |
    |                                    Accept contract  |                       |
    |                                  ( Add buyer Xpub ) |                       |
    |                                    Process policy   |                       |
    |                                                     |                       |
    | <--------------- Accept contract ------------------ |                       |
    |                                                     |                       |
    |                                                     | ---- Lock funds ----> |
    |                                                     |    (on-chain tx)      |
    |                                                     |                       |
    |                                                     |                       |
    |            /* contract execution */                 |                       |
    |                                                     |                       |
    |                                                     |                       |
    |                                                     |                       |
    |                                                     |                       |
    | <------- Unlock contract (hash/signature) --------- |                       |
    |                                                     |                       |
    | ----------------------------- Spend funds --------------------------------> |
    |                                                          (on-chain tx)      |
```
## Contract Signatures

Some contract steps have to be signed by either one or both main parties (buyer/seller). By signing, we mean signing a hash 
of the contract state. As the contract state evolves, not all fields are hashed at all times; they have to be chosen depending on the state:

### Offered:

```
h = sha256(
  state |
  contract_type |
  total_amount |
  deposit |
  timelock |
  details |
  buyer_pubkey |
  seller_pubkey |
  (third_parties)
)
```

### Accepted:

```
h = sha256(
  state |
  contract_type |
  total_amount |
  deposit |
  timelock |
  details |
  buyer_pubkey |
  seller_pubkey |
  seller_xpub |
  buyer_xpub |
  buyer_hash |
  address|
  (third_parties)
)
```

## Spending policy

The contract is formalized into a Miniscript spending policy that contains 2 mandatory 'paths' 
and some optional paths.

### 1 - Normal spending path (mandatory)

The principal spending path, the one which an agreement issue of the contract execution should
end with, is a hashlock path of type:

`and(pk(seller), sha256(buyer_hash))`

buyer_hash is the sha256 hash of a preimage, where the preimage is the buyer's identity private key tweaked 
by the contract hash at the 'Accepted' state. The buyer communicates the preimage after agreement on the contract's
normal issuance.

A hashlocked type has been chosen for this path in order to let the seller spend UTXO(s) without asking a signature
from the buyer, most easily managed in case of RBF or to let the seller spend the coins later.
Note: in case of an optional timelock where the buyer can use solely their own signature to spend the coin(s), it's not safe
to NOT spend the coins before the timelock has elapsed, else the buyer can perform a CANCEL tx after the timelock has elapsed.

### 2 - Refund/Backup path (mandatory)

The refund spending path is a path of type:

`and(pk(seller), pk(buyer))`

This path can be used if both parties agree to a refund to the buyer.

### 3 - Timelocked spending path (optional)

Timelocked paths can be used for 2 main reasons:
 - If the execution of the contract has to be done before a certain date/time, otherwise
   the contract is canceled and the buyer refunded. This path should have a policy of type:

   `and(older(relative_timelock), pk(buyer))`

   or 

   `and(after(absolute_timelock), pk(buyer))`

 - Have timelocked 3rd party intervention, the policy could be of type:
   

   `and(older(relative_timelock), 3rdparty_policy)`

   or 

   `and(after(absolute_timelock), 3rdparty_policy)`

### 4 - 3rd parties policies

Adding a 3rd party to a spending path could be done for 2 reasons:
  - Escrow function: the 3rd party's role is to determine which of the seller/buyer is 'honest'
    and cooperate with them to unlock the stuck contract by cosigning with the 'honest' participant 
    a transaction that resolves the conflict. The policy can be of type:

    `thresh(2, pk(seller), pk(buyer), pk(3rd_party))`

    This can replace `3rdparty_policy` in a timelocked path, thanks to Miniscript composability.

  - Recovery partner: the 3rd party is in a timelock position to replace one of the participants, in case of
    lost keys. For instance, the policy can be of type:

    `or(pk(seller), after(absolute_timelock))`

    and can replace `pk(seller)` in the mandatory path.

### Advanced scripting

More advanced scripting can be done, using the full potential of Miniscript, especially in a corporate context
where companies often use multisigs or complex setups.
