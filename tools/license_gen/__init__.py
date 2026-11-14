"""Offline Shapoclyack product-license generator (Ed25519 signer).

Vendor-only CLI: signs ``shapoclyack-license`` v1 documents. The private key
never ships in the product image; the control plane verifies with a pinned
public key. See ``docs/adr/0007-product-licensing.md``.
"""
