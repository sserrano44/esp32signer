#include "rpc.h"
#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "eth_signer.h"
#include "eth_tx.h"
#include "hex.h"
#include "led.h"
#include "policy.h"
#include "signer_app.h"
#include "store.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "rpc";

#define ERR_PARSE -32700
#define ERR_INVALID_REQ -32600
#define ERR_METHOD -32601
#define ERR_PARAMS -32602
#define ERR_INTERNAL -32603
#define ERR_REJECTED -32003 /* EIP-1474 "Transaction rejected" */

static char *respond(const cJSON *id, cJSON *result, int code, const char *msg)
{
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "jsonrpc", "2.0");
    cJSON_AddItemToObject(r, "id", id ? cJSON_Duplicate(id, 1) : cJSON_CreateNull());
    if (code) {
        cJSON *e = cJSON_AddObjectToObject(r, "error");
        cJSON_AddNumberToObject(e, "code", code);
        cJSON_AddStringToObject(e, "message", msg);
    } else {
        cJSON_AddItemToObject(r, "result", result);
    }
    char *s = cJSON_PrintUnformatted(r);
    cJSON_Delete(r);
    return s;
}

static char *m_accounts(const cJSON *id)
{
    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, cJSON_CreateString(g_app.address_hex));
    return respond(id, arr, 0, NULL);
}

static char *m_status(const cJSON *id)
{
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "firmware", esp_app_get_description()->version);
    cJSON_AddStringToObject(r, "address", g_app.address_hex);
    cJSON_AddStringToObject(r, "policy_sha256", g_app.policy_hash);
    cJSON_AddStringToObject(r, "hostname", g_app.hostname);
    cJSON_AddNumberToObject(r, "uptime_s", (double)(esp_timer_get_time() / 1000000));
    cJSON_AddNumberToObject(r, "signed", g_app.n_signed);
    cJSON_AddNumberToObject(r, "rejected", g_app.n_rejected);
    cJSON_AddNumberToObject(r, "auth_failures", g_app.n_auth_fail);
    cJSON_AddNumberToObject(r, "free_heap", (double)esp_get_free_heap_size());
    cJSON_AddNumberToObject(r, "free_internal", (double)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(r, "min_free_internal", (double)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(r, "largest_internal_block",
                            (double)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    cJSON_AddNumberToObject(r, "free_psram", (double)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    return respond(id, r, 0, NULL);
}

static char *m_sign_tx(const cJSON *id, const cJSON *params)
{
    const cJSON *txj = cJSON_IsArray(params) ? cJSON_GetArrayItem(params, 0) : NULL;
    if (!cJSON_IsObject(txj)) return respond(id, NULL, ERR_PARAMS, "params must be [transaction]");

    eth_tx_t *tx = malloc(sizeof(eth_tx_t));
    uint8_t *raw = malloc(ETH_TX_MAX_ENCODED);
    char *out = NULL;
    if (!tx || !raw) {
        out = respond(id, NULL, ERR_INTERNAL, "out of memory");
        goto done;
    }

    char err[160];
    if (eth_tx_from_json(txj, tx, err, sizeof(err)) != 0) {
        out = respond(id, NULL, ERR_PARAMS, err);
        goto done;
    }
    if (tx->has_from && memcmp(tx->from, g_app.address, 20) != 0) {
        out = respond(id, NULL, ERR_PARAMS, "'from' does not match the signer address");
        goto done;
    }

    char tohex[43] = "(create)", sel[11] = "-";
    if (tx->has_to) addr_to_hex(tx->to, tohex);
    if (tx->data_len >= 4) {
        sel[0] = '0';
        sel[1] = 'x';
        hex_encode(tx->data, 4, sel + 2);
    }

    xSemaphoreTake(g_app.lock, portMAX_DELAY);
    policy_result_t pr;
    int64_t t0 = esp_timer_get_time();
    policy_check(g_app.policy, tx, (uint64_t)(t0 / 1000), &pr);
    if (!pr.allowed) {
        g_app.n_rejected++;
        xSemaphoreGive(g_app.lock);
        ESP_LOGW(TAG, "REJECT chain=%llu nonce=%llu to=%s sel=%s: %s", (unsigned long long)tx->chain_id,
                 (unsigned long long)tx->nonce, tohex, sel, pr.reason);
        char msg[200];
        snprintf(msg, sizeof(msg), "rejected by policy: %s", pr.reason);
        out = respond(id, NULL, ERR_REJECTED, msg);
        goto done;
    }

    uint8_t key[32], txhash[32];
    size_t len = 0;
    int rc = -1;
    if (store_get_fixed(STORE_KEY_PRIVKEY, key, 32) == ESP_OK)
        rc = eth_tx_sign(tx, key, raw, ETH_TX_MAX_ENCODED, &len, txhash);
    eth_memzero(key, sizeof(key));
    if (rc == 0) g_app.n_signed++;
    xSemaphoreGive(g_app.lock);
    if (rc != 0) {
        out = respond(id, NULL, ERR_INTERNAL, "signing failed");
        goto done;
    }

    char hh[65];
    hex_encode(txhash, 32, hh);
    ESP_LOGI(TAG, "SIGN chain=%llu nonce=%llu to=%s sel=%s rule=%s tx=0x%s (%lld us)",
             (unsigned long long)tx->chain_id, (unsigned long long)tx->nonce, tohex, sel, pr.reason, hh,
             (long long)(esp_timer_get_time() - t0));
    led_flash();

    char *rawhex = malloc(len * 2 + 3);
    if (!rawhex) {
        out = respond(id, NULL, ERR_INTERNAL, "out of memory");
        goto done;
    }
    rawhex[0] = '0';
    rawhex[1] = 'x';
    hex_encode(raw, len, rawhex + 2);
    out = respond(id, cJSON_CreateString(rawhex), 0, NULL);
    free(rawhex);

done:
    free(tx);
    free(raw);
    return out;
}

char *rpc_handle(const char *body, size_t len)
{
    cJSON *req = cJSON_ParseWithLength(body, len);
    if (!req) return respond(NULL, NULL, ERR_PARSE, "parse error");
    char *out;
    if (cJSON_IsArray(req)) {
        out = respond(NULL, NULL, ERR_INVALID_REQ, "batch requests are not supported");
        goto done;
    }
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(req, "id");
    const cJSON *method = cJSON_GetObjectItemCaseSensitive(req, "method");
    const cJSON *params = cJSON_GetObjectItemCaseSensitive(req, "params");
    if (!cJSON_IsObject(req) || !cJSON_IsString(method)) {
        out = respond(id, NULL, ERR_INVALID_REQ, "invalid request");
        goto done;
    }
    const char *m = method->valuestring;
    if (!strcmp(m, "eth_signTransaction"))
        out = m_sign_tx(id, params);
    else if (!strcmp(m, "eth_accounts") || !strcmp(m, "eth_requestAccounts"))
        out = m_accounts(id);
    else if (!strcmp(m, "signer_status"))
        out = m_status(id);
    else
        out = respond(id, NULL, ERR_METHOD, "method not supported (only eth_signTransaction, eth_accounts, signer_status)");
done:
    cJSON_Delete(req);
    return out;
}
