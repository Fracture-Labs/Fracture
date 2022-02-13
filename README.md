# Umbral-IPFS
> Implementing the Umbral threshold proxy re-encryption scheme with IPFS

# Usage

```
cat data.txt | umbral_ipfs encrypt \
  --pk $ALICE_PK

# Outputs
# cipher: ABCD
# signer: EFGH

cat cipher.txt | umbral_ipfs grant
  --signer EFGH 
  --fragments 3 \
  --threshold 2 \
  --sk $ALICE_SK \
  --pk $BOB_PK

# Outputs
# key frag: XXX
# key frag: YYY
# key frag: ZZZ
# capsule: CDEF
# cipher: ABCD
```