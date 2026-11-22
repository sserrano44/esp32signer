#include "button.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char *TAG = "button";
static uint32_t s_long_ms;
static void (*s_cb)(void);

void button_init(void)
{
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << CONFIG_SIGNER_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    gpio_config(&io);
}

bool button_pressed(void)
{
    return gpio_get_level(CONFIG_SIGNER_BUTTON_GPIO) == 0;
}

bool button_wait_press(uint32_t ms)
{
    int held = 0;
    for (uint32_t t = 0; t < ms; t += 20) {
        held = button_pressed() ? held + 1 : 0;
        if (held >= 3) return true; /* ~60 ms debounce */
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    return false;
}

static void watch_task(void *arg)
{
    uint32_t held = 0;
    for (;;) {
        held = button_pressed() ? held + 50 : 0;
        if (held >= s_long_ms) {
            ESP_LOGW(TAG, "long press detected");
            s_cb();
            held = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

void button_watch_long_press(uint32_t ms, void (*cb)(void))
{
    s_long_ms = ms;
    s_cb = cb;
    xTaskCreate(watch_task, "button", 2560, NULL, 3, NULL);
}
