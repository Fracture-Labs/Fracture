# Fracture

Fracture implements the Umbral threshold proxy reincryption scheme. It also
contains the HTTP-based backend code Constitute plugs into.

## Future Goals

This being a POC, there are many aspects of Fracture we want to improve:

- WASM, ideally Constitute and Fracture should be encapsulated to run on a single device from the user's perspective.
- Custom networking stack, likely not HTTP-based.
- Network layer encryption.
- Network discovery.
- Custom storage layer, perhaps an IPFS cluster.
