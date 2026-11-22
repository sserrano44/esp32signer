# bitcoin-core/libsecp256k1 v0.7.1 (vendored in ./secp256k1, unmodified).
# Only signing is used on-device, so the verification table is kept minimal
# (ECMULT_WINDOW_SIZE=2) and the 22 KB default comb table is used for ecmult_gen.
idf_component_register(
    SRCS "secp256k1/src/secp256k1.c"
         "secp256k1/src/precomputed_ecmult.c"
         "secp256k1/src/precomputed_ecmult_gen.c"
    INCLUDE_DIRS "secp256k1/include"
    PRIV_INCLUDE_DIRS "secp256k1/src" "secp256k1")
target_compile_definitions(${COMPONENT_LIB} PRIVATE ENABLE_MODULE_RECOVERY=1 ECMULT_WINDOW_SIZE=2)
target_compile_options(${COMPONENT_LIB} PRIVATE -w)
