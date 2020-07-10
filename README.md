# GoodPassport
Ethereum Zero Knowledge Proof of Passport

Based on work done by [Jan](https://github.com/rgex) for [UBIC](https://github.com/UBIC-repo/core)
GQ algorithm can be found [here](https://github.com/rgex/new-GQ-implementation-for-UBIC) and [here](https://crypto.stackexchange.com/questions/81094/proving-the-knowlege-of-e-th-root-in-an-non-interactive-way) 

- This repo contains smart contracts implementations for verifying GQ ZK proof of knowledge of signature.
- User submit a proof that he knows a valid signature by a trusted 3rd party who's public key is stored on-chain.
- This can be used to verify a user knows a signature contained in e-documents issued by trusted 3rd parties.

- A Javascript helper is also supplied to generate proofs.
