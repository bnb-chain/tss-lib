Multi-party ECDSA
=====================================

This project is a Go implementation of {t,n}-threshold ECDSA (elliptic curve digital signature algorithm).

This library includes three protocols:

* Key Generation for creating secret shares.
* Signing for using the secret shares to generate a signature.
* Dynamic Groups to change the group of participants while keeping the secret.

ECDSA is used extensively for crypto-currencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve) and much more. 
This library can be used to create MultiSig and ThresholdSig crypto wallets.

Resources
-------------------

https://eprint.iacr.org/2019/114.pdf
