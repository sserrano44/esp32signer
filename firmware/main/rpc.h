#pragma once
#include <stddef.h>

/* Handle one JSON-RPC 2.0 request body; returns a malloc'ed JSON response. */
char *rpc_handle(const char *body, size_t len);
