#pragma once

/* Run the USB provisioning console. Never returns (reboots on exit/timeout). */
void provision_run(void) __attribute__((noreturn));
