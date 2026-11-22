# Host (macOS/Linux) unit tests for the portable firmware components.
#   cmake -S firmware/test_host -B build-test && cmake --build build-test && ctest --test-dir build-test --output-on-failure
cmake_minimum_required(VERSION 3.16)
project(esp32signer_host_tests C)

set(CMAKE_C_STANDARD 11)
set(COMP ${CMAKE_CURRENT_LIST_DIR}/../components)
set(SECP ${COMP}/secp256k1/secp256k1)

if(DEFINED ENV{IDF_PATH})
  set(IDF_PATH_DEFAULT $ENV{IDF_PATH})
else()
  set(IDF_PATH_DEFAULT $ENV{HOME}/esp/esp-idf)
endif()
set(CJSON_DIR ${IDF_PATH_DEFAULT}/components/json/cJSON CACHE PATH "cJSON source dir")

add_library(secp256k1_host STATIC
  ${SECP}/src/secp256k1.c
  ${SECP}/src/precomputed_ecmult.c
  ${SECP}/src/precomputed_ecmult_gen.c)
target_include_directories(secp256k1_host PUBLIC ${SECP}/include PRIVATE ${SECP}/src ${SECP})
target_compile_definitions(secp256k1_host PRIVATE ENABLE_MODULE_RECOVERY=1 ECMULT_WINDOW_SIZE=2)
target_compile_options(secp256k1_host PRIVATE -w)

add_library(cjson_host STATIC ${CJSON_DIR}/cJSON.c)
target_include_directories(cjson_host PUBLIC ${CJSON_DIR})

add_library(core_host STATIC
  ${COMP}/ethcore/hex.c
  ${COMP}/ethcore/keccak256.c
  ${COMP}/ethcore/rlp.c
  ${COMP}/ethcore/tx.c
  ${COMP}/ethcore/tx_json.c
  ${COMP}/ethcore/signer.c
  ${COMP}/policy/regex.c
  ${COMP}/policy/policy.c)
target_include_directories(core_host PUBLIC ${COMP}/ethcore/include ${COMP}/policy/include)
target_link_libraries(core_host PUBLIC secp256k1_host cjson_host)
target_compile_options(core_host PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter
  $<$<C_COMPILER_ID:Clang,AppleClang,GNU>:-fsanitize=address,undefined>)
target_link_options(core_host PUBLIC $<$<C_COMPILER_ID:Clang,AppleClang,GNU>:-fsanitize=address,undefined>)

add_executable(test_ethcore test_ethcore.c)
target_link_libraries(test_ethcore core_host)
add_executable(test_policy test_policy.c)
target_link_libraries(test_policy core_host)

enable_testing()
add_test(NAME ethcore COMMAND test_ethcore ${CMAKE_CURRENT_LIST_DIR}/vectors.json)
add_test(NAME policy COMMAND test_policy)

# Policy evaluation CLI used by host/tests/test_policy_compiler.py
add_executable(policy_cli policy_cli.c)
target_link_libraries(policy_cli core_host)
