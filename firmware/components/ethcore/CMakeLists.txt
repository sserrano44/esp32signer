# Portable Ethereum primitives (no ESP-IDF dependencies besides cJSON).
idf_component_register(
    SRCS "hex.c" "keccak256.c" "rlp.c" "tx.c" "tx_json.c" "signer.c"
    INCLUDE_DIRS "include"
    REQUIRES json secp256k1)
