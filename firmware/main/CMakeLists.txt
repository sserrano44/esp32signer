idf_component_register(
    SRCS "app_main.c" "button.c" "led.c" "provision.c" "wifi.c" "discovery.c"
         "https_server.c" "rpc.c" "signer_app.c"
    INCLUDE_DIRS "."
    REQUIRES ethcore policy store json mbedtls esp_wifi esp_netif esp_event nvs_flash
             esp_https_server esp_http_server esp_driver_gpio esp_driver_usb_serial_jtag
             bootloader_support esp_timer esp_app_format)
