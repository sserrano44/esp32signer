#pragma once

typedef enum {
    LED_OFF,
    LED_BOOT_WINDOW, /* white blink: press BOOT now to provision */
    LED_PROVISION,   /* solid blue */
    LED_CONNECTING,  /* yellow blink */
    LED_READY,       /* dim green */
    LED_ERROR,       /* red blink */
} led_state_t;

void led_init(void);
void led_set(led_state_t s);
/* Short white flash (one per signature), then back to the current state. */
void led_flash(void);
