/* Host tool: evaluate JSON-RPC transactions against a canonical policy with the
 * exact device engine. Used by host/tests to cross-check the Python compiler.
 *   policy_cli policy.json 0xSELF txs.json   ->  one "ALLOW|DENY reason" line per tx
 */
#include "cJSON.h"
#include "eth_tx.h"
#include "hex.h"
#include "policy.h"
#include "test_util.h"

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s policy.json self_address txs.json\n", argv[0]);
        return 2;
    }
    size_t plen;
    char *pjson = read_file(argv[1], &plen), *tjson = read_file(argv[3], NULL);
    uint8_t self[20];
    if (!pjson || !tjson || addr_from_hex(argv[2], self) != 0) {
        fprintf(stderr, "bad input\n");
        return 2;
    }
    policy_t *p;
    char err[200];
    if (policy_load(pjson, plen, self, &p, err, sizeof(err)) != 0) {
        fprintf(stderr, "policy_load: %s\n", err);
        return 2;
    }
    cJSON *arr = cJSON_Parse(tjson), *t;
    eth_tx_t *tx = malloc(sizeof(eth_tx_t));
    uint64_t now = 0;
    cJSON_ArrayForEach(t, arr)
    {
        if (eth_tx_from_json(t, tx, err, sizeof(err)) != 0) {
            printf("DENY parse: %s\n", err);
            continue;
        }
        policy_result_t r;
        policy_check(p, tx, now += 60000, &r); /* spaced out: rate limit never hit */
        printf("%s %s\n", r.allowed ? "ALLOW" : "DENY", r.reason);
    }
    free(tx);
    cJSON_Delete(arr);
    policy_free(p);
    free(pjson);
    free(tjson);
    return 0;
}
