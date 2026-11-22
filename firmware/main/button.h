#pragma once
#include <stdbool.h>
#include <stdint.h>

void button_init(void);
bool button_pressed(void);
/* Poll for a press during `ms` milliseconds. */
bool button_wait_press(uint32_t ms);
/* Background task: holding the button for `ms` calls `cb`. */
void button_watch_long_press(uint32_t ms, void (*cb)(void));
