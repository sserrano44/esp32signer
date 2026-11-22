#include "led.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "led_strip.h"
#include "sdkconfig.h"

static const char *TAG = "led";
static led_strip_handle_t s_strip;
static volatile led_state_t s_state = LED_OFF;
static volatile int s_flash;

#define BRIGHT 24

static void show(uint8_t r, uint8_t g, uint8_t b)
{
    if (!s_strip) return;
    led_strip_set_pixel(s_strip, 0, r, g, b);
    led_strip_refresh(s_strip);
}

static void led_task(void *arg)
{
    unsigned tick = 0;
    for (;;) {
        tick++;
        bool on = (tick / 3) % 2; /* ~300 ms blink */
        if (s_flash) {
            s_flash = 0;
            show(BRIGHT * 3, BRIGHT * 3, BRIGHT * 3);
            vTaskDelay(pdMS_TO_TICKS(60));
        }
        switch (s_state) {
        case LED_OFF: show(0, 0, 0); break;
        case LED_BOOT_WINDOW: on ? show(BRIGHT, BRIGHT, BRIGHT) : show(0, 0, 0); break;
        case LED_PROVISION: show(0, 0, BRIGHT * 2); break;
        case LED_CONNECTING: on ? show(BRIGHT, BRIGHT / 2, 0) : show(0, 0, 0); break;
        case LED_READY: show(0, BRIGHT / 2, 0); break;
        case LED_ERROR: on ? show(BRIGHT * 2, 0, 0) : show(0, 0, 0); break;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void led_init(void)
{
    led_strip_config_t cfg = {
        .strip_gpio_num = CONFIG_SIGNER_LED_GPIO,
        .max_leds = 1,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
    };
    led_strip_rmt_config_t rmt = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
    };
    if (led_strip_new_rmt_device(&cfg, &rmt, &s_strip) != ESP_OK) {
        ESP_LOGW(TAG, "no status LED on GPIO %d", CONFIG_SIGNER_LED_GPIO);
        s_strip = NULL;
    }
    xTaskCreate(led_task, "led", 2560, NULL, 2, NULL);
}

void led_set(led_state_t s)
{
    /* Error is latched: only entering provision mode clears it. */
    if (s_state == LED_ERROR && s != LED_PROVISION) return;
    s_state = s;
}

void led_flash(void)
{
    s_flash = 1;
}
