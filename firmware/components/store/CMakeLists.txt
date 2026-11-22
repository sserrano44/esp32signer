idf_component_register(
    SRCS "store.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash nvs_sec_provider)
