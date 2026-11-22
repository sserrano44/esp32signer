# Portable policy engine + linear-time regex.
idf_component_register(
    SRCS "policy.c" "regex.c"
    INCLUDE_DIRS "include"
    REQUIRES ethcore json)
