# Umbral-IPFS
> Implementing the Umbral threshold proxy re-encryption scheme with IPFS

# Usage

```
umbral_ipfs account

# Outputs (needs to be run 2x, once for sender, once for receiver):
# *_SK
# *_PK

umbral_ipfs encrypt \
  --sender-pk <SENDER_PK> \
  --plaintext <PLAINTEXT>

# Outputs:
# CAPSULE
# CIPHERTEXT

umbral_ipfs grant \
  --sender-sk <SENDER_SK> \
  --receiver-pk <RECEIVER_PK> \
  --threshold <THRESHOLD> \
  --shares <SHARES>

# Outputs:
# VERIFYING_PK
# KFRAG
# KFRAG
# ...

umbral_ipfs pre \
  --capsule-cid <CAPSULE_CID> \
  --kfrag <KFRAG> \
  --sender-pk <SENDER_PK> \
  --receiver-pk <RECEIVER_PK> \
  --verifying-pk <VERIFYING_PK>

# Outputs:
# CFRAG
# CFRAG
# ...

umbral_ipfs decrypt \
  --capsule-cid <CAPSULE_CID> \
  --ciphertext-cid <CIPHERTEXT_CID> \
  --cfrags <[CFRAG]> \
  --sender-pk <SENDER_PK> \
  --receiver-sk <RECEIVER_SK> \
  --receiver-pk <RECEIVER_PK> \
  --verifying-pk <VERIFYING_PK>

# Outputs:
# PLAINTEXT
```
