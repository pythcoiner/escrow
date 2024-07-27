## Escrow

This project is an experimental Bitcoin 'Wallet' build around a peer-to-peer escrow contract
using miniscript & taproot.

## Abstract

The idea is to have bitcoin wallet with the given properties:
 - Single purpose: only aim to interract w/ escrow contracts.
 - Self custody: you (and nobody else) own your cryptographics secrets.
 - Trustless: the escrow contract do not rely on any 3rd party ACKing the contract, they are optionnal
   and are aimed to interact in last-resort or recovery case only.
 - Peer-to-peer: contract is not 'hosted' nor 'executed' by a central coordinator. Middle-partys 
   (like a nostr-relay) can be used as a transport: they carry an encrypted data package but do not know
   about the payload.
 - Secured by bitcoin (mini)script.
 - Use Taproot & hashlocks.

The contract is the data representing terms of a deal to be executed, including but not limited to:
 - Cryptographic identities of participants (Seller, Buyer, 3rd partys)
 - Amount that should be paid.
 - Optional deposits than can be spend directly by seller before contract execution.
 - Textual description of the terms (can also include hash of attached documents).
 - Anything that can be represented as string(s) or byte(s).

## Motivation
Traditional escrow services rely on centralized third parties. By using Bitcoin's scripting capabilities, 
especially miniscript and Taproot, this solution ensures self-custody and trustless transactions, eliminating 
the need for intermediaries.

The peer-to-peer architecture means the contract is not dependent on any central coordinator, enhancing privacy 
and security. By leveraging hashlocks and Taproot, the project offers efficient and flexible transaction structures. 

## Contract steps

The contract lifetime is composed by several steps:
 - Offered: The seller offer a contract after a preliminar negociation.
 - Refused: The buyer can refuse contract terms, in order to renegociate or cancel the contract.
 - Accepted: The buyer had accepted terms of contract.
 - Funded: The buyer has broadcast an (or several) utxo(s) matching the contract total amount, but
   the block confirmation target is not yet reach.
 - Locked: Funded + blocks confirmation target is reach.
 - Unlocked: The seller can now spend utxo(s) w/o buyer consent.
 - Disputed: Buyer and seller do not agree on the issue of contract execution, coins are locked in
   contract until they find an agreement or third party action and/or timelock elapsed.

 The contract lifetime can be represented by this chart: 

 ```

        ┌───────────┐        ┌───────────┐
        │  Offered  │◄───────│  Refused  │
        └───────────┘        └───────────┘
          │       │                 ▲  
     buyer accept └─ buyer refuse ──┘
          │                          
          ▼
        ┌───────────┐
        │ Accepted  │
        └───────────┘
              │
  buyer broadcast funding tx        
              │
              ▼
        ┌───────────┐
        │  Funded   │
        └───────────┘
              │
 utxo reach <target> confirmations           
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
                        timelock elapse           3rd party take
                                                      action
```

## Identities

Identities of the contract participants are materialized by a key pair that permit:
 - Message signature, in our case signing states of the contract.
 - Message encryption
 - Authentication
 - Hashlock secret generation

This implementation use secp256k1 keys and messaging transport over Nostr protocol.
Contract data are dumped as a json 'payload' and actually 'wrapped' into a Nostr NIP05 "Encrypted Direct Messages",
we should switch in the future to NIP17 "Private Direct Messages".

### XPubs/Derivation paths

For privacy & security matters we should not produce contract with duplicate signing keys. Some signing device 
have some known limitations in their design like a max derivation depth of 8.

 - BIP388 restrict the XPub derivation paath to <multipath>/* (depth of 2).
 - Our contract hash is a 32 bytes array ([u8:32]) that we can converty into a 8 u32 array ([u32;8]).
 - Given this context we opt for a XPub origin derivation path of depth 6 + a depth 2 for the XPub derivation path.
 - Contracts typically produce a single receive address, so static childs numbers are used instead of multipaths and wildcards

Special case of 3rd parties:

Third parties are kept unaware of contract details unless a dispute arises. These parties provide a single public XPub. 
Due to BIP 388 limitations, the entropy for this xpub derivation path is 2 bytes, as it is limited to 2 levels.
Non-hardened derivation paths are used to maintain compatibility with hardware signing devices. The maximum value 
for an unhardened derivation path is 2^31-1, meaning each byte from the contract hash provides 7 bits of entropy.

## Contract fields
```
|------------------|-------------------|-------------------------------------------------------------------|
|       Field      |        Type       | Description                                                       |
|:----------------:|:-----------------:|:------------------------------------------------------------------|
|      version     |        u32        | Version of the contract structure                                 |
|------------------|-------------------|-------------------------------------------------------------------|
|        id        |      [u8;32]      | The contract id is a sha256 hash of the contract datastructure    |
|------------------|-------------------|-------------------------------------------------------------------|
|  contract_state  |         u8        | The contract actual state:                                        |
|                  |                   | - Empty                                                           |
|                  |                   | - Offered (seller pre-fill and sign this state)                   |
|                  |                   | - Accepted (buyer fill and sign this state)                       |
|                  |                   | - Refused ( buyer update and sign contract if he ask for changes) |
|                  |                   | - Funded ( Unconfirmed payment)                                   |
|                  |                   | - Locked ( Confirmed payment )                                    |
|                  |                   | - Unlocked ( Buyer shared hash to seller)                         |
|------------------|-------------------|-------------------------------------------------------------------|
|   contract_type  |         u8        | The contract can be of several kinds:                             |
|                  |                   | - Peer to peer                                                    |
|                  |                   | - Peer to peer with timelock                                      |
|                  |                   | - Peer to peer with escrow(s)                                     |
|                  |                   | - Peer to peer with escrow(s) & timelock                          |
|                  |                   | - ....                                                            |
|------------------|-------------------|-------------------------------------------------------------------|
|   total_amount   |        i64        | The bitcoin total amount of the contract (in sats)                |
|------------------|-------------------|-------------------------------------------------------------------|
|      deposit     |        i64        | Amount of deposit (optionnal)                                     |
|------------------|-------------------|-------------------------------------------------------------------|
|     timelock     |        u32        | Timelock of the contract in bitcoin blocks (optionnal)            |
|------------------|-------------------|-------------------------------------------------------------------|
|      details     |       string      | A text describing the contract between parties                    |
|------------------|-------------------|-------------------------------------------------------------------|
|       buyer      |      pub_key      | Buyer (nostr) public key                                          |
|------------------|-------------------|-------------------------------------------------------------------|
|      seller      |      pub_key      | Seller (nostr) public key                                         |
|------------------|-------------------|-------------------------------------------------------------------|
|   third_parties  | [(pub_key, xpub)] | A list of thirds parties that can interract as escrow(s) in       |
|                  |                   | case of dispute. (optionnal)                                      |
|------------------|-------------------|-------------------------------------------------------------------|
|  buyer_signature |                   | See [buyer signature details](#buyer-signature)                   |
|------------------|-------------------|-------------------------------------------------------------------|
| seller_signature |                   | See [seller signature details](#seller-signature)                 |
|------------------|-------------------|-------------------------------------------------------------------|
|  contract_policy |                   | The `miniscript` policy representing the contract spending        |
|                  |                   | conditions, see [policy section](#contract-policy)                |
|------------------|-------------------|-------------------------------------------------------------------|
```

## Communication Flow in case both partie aggree on contract issue:
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
    |                                                     |    ( on-chain tx )    |
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
    |                                                          ( on-chain tx )    |
```

## Contract Signatures

Some contract steps have to be signed by either one or both main parties (buyer/seller). By signing we means signing a hash 
of the contract state, as the contract state evolve, not all fields are hashed at every times, they have to been 
choosed depending the state:

### Offered:
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

### Accepted:

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
  adress|
  (third_parties)
)

## Spending policy

The contract is formalized into a miniscript spending policy that contains 2 mandatory 'path' 
and some optionals path.

### 1 - Normal spending path (mandatory)

The principal spending path , the one wich an agreement issue of the contract execution should
end with is a hashlock path of type:

`and(pk(seller), sha256(buyer_hash))`

`buyer_hash` is the sha256 hash of a preimage, where preimage is the buyer identity private key tweaked 
by the contract hash at 'Accepted' state. The Buyer communicate the preimage after agreement on the contract
normal issuance.

An hashlocked type have been decided for this path in order to let the seller spends utxo(s) w/o asking a signature
to buyer, most easy to manage in case of RBF or in order to let the seller spend the coins later.
Note: in case of a optionnal timelock where the buyer can use solely its own signature to spend the coin(s), it's not safe
to NOT spend the coins before the timelock elapsed, else the buyer can do a CANCEL tx after the timelock elapsed.

### 2 - Refund/Backup path (mandatory)

The refund spending path is a path of type:

`and(pk(seller), pk(buyer))`

this path can be use if both parties agree to a refund to the buyer.

### 3 - Timelocked spending path (optional)

Timelocked path can be used for 2 main reasons:
 - If the execution of the contract have to been done before a certain date/time, else
   the contract is canceled and the buyer refunded, this path should have a policy of type:

   `and(older(relative_timelock), pk(buyer))`

   or 

   `and(after(absolute_timelock), pk(buyer))`

 - Have timelocked 3rd party intervention, the policy could be of type:
   

   `and(older(relative_timelock), 3rdparty_policy)`

   or 

   `and(after(absolute_timelock), 3rdparty_policy)`

### 4 - 3rd parties policies

Adding 3rd party to a spending path could be done for 2 reasons:
  - Escrow function, the 3rd  party role is to determine wich of the seller/buyer is 'honnest'
    and cooperate w/ him to unlock the stuck contract by cosigning with the 'honnest' participant 
    a tx that resolve the conflict, the policy can be of type:

    `thresh(2, pk(seller), pk(buyer), pk(3rd_party))`

    and can replace <3rdparty_policy> in a timelocked path for instance thanks to minisccript composability.

  - Recovery partner, the 3rd party is in a timelock position for replace one of the participant, in case of
    lost of keys, for instance, the policy can be of type

    `or(pk(seller), after(absolute_timelock))`

    and can replace `pk(seller)` in the mandatories path for instance.

### Advanced scripting

More advanced scpitpting can be done, using the full potential of miniscript, especially in a corporate context
where the companies often use multisigs or complexes setups.


