// Test harness for the Infinite Noise TRNG OpenSSL provider.
//
// Tests both the libinfnoise C library directly and the OpenSSL provider
// through the EVP_RAND and RAND_bytes APIs. All hardware-dependent tests
// are skipped with a clear message if no device is detected.
//
// Build:
//   gcc -O2 -Wall -Wextra -I/usr/include/libftdi1
//       -o test_infnoise_prov test_infnoise_prov.c
//       -lcrypto -linfnoise -lm
//
// Run:
//   OPENSSL_CONF=infnoise-provider.cnf ./test_infnoise_prov
//   or:
//   OPENSSL_MODULES=/usr/lib/ossl-modules ./test_infnoise_prov

#include <libinfnoise.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

///////////////////////
// Test framework
///////////////////////

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_skipped = 0;
static int hw_detected = 0;

#define CLR_RESET "\033[0m"
#define CLR_GREEN "\033[32m"
#define CLR_RED   "\033[31m"
#define CLR_YELLOW "\033[33m"
#define CLR_BLUE  "\033[34m"
#define CLR_BOLD  "\033[1m"

static void test_pass(const char *name)
{
    tests_run++;
    tests_passed++;
    printf("  " CLR_GREEN "PASS" CLR_RESET "  %s\n", name);
}

static void test_fail(const char *name, const char *fmt, ...)
{
    va_list ap;
    tests_run++;
    tests_failed++;
    printf("  " CLR_RED "FAIL" CLR_RESET "  %s: ", name);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void test_skip(const char *name, const char *reason)
{
    tests_run++;
    tests_skipped++;
    printf("  " CLR_YELLOW "SKIP" CLR_RESET "  %s: %s\n", name, reason);
}

static void section(const char *title)
{
    printf("\n" CLR_BOLD CLR_BLUE "--- %s ---" CLR_RESET "\n", title);
}

/////////////////////////////////////////////
// Layer 1: Direct libinfnoise hardware tests
/////////////////////////////////////////////

static void test_hw_detect(void)
{
    const char *name = "hw_detect";
    const char *msg = NULL;
    infnoise_devlist_node_t *devs = listUSBDevices(&msg);

    if (devs == NULL) {
        test_skip(name, "no Infinite Noise TRNG detected via USB");
        return;
    }

    hw_detected = 1;
    int count = 0;
    infnoise_devlist_node_t *cur = devs;
    while (cur != NULL) {
        count++;
        printf("         device %d: %s / %s / serial=%s\n",
               count, cur->manufacturer, cur->description, cur->serial);
        cur = cur->next;
    }

    // Free the device list.
    cur = devs;
    while (cur != NULL) {
        infnoise_devlist_node_t *next = cur->next;
        free(cur);
        cur = next;
    }

    test_pass(name);
}

static void test_hw_init_deinit(void)
{
    const char *name = "hw_init_deinit";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    struct infnoise_context ctx;
    memset(&ctx, 0, sizeof(ctx));

    bool ok = initInfnoise(&ctx, NULL, true, false);
    if (!ok) {
        test_fail(name, "initInfnoise failed: %s",
                  ctx.message ? ctx.message : "unknown");
        return;
    }
    deinitInfnoise(&ctx);
    test_pass(name);
}

static void test_hw_read_raw(void)
{
    const char *name = "hw_read_raw";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    struct infnoise_context ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (!initInfnoise(&ctx, NULL, true, false)) {
        test_fail(name, "initInfnoise failed");
        return;
    }

    uint8_t buf[BUFLEN];
    uint32_t n = readData(&ctx, buf, false, 1);
    deinitInfnoise(&ctx);

    if (ctx.errorFlag) {
        test_fail(name, "readData error: %s",
                  ctx.message ? ctx.message : "unknown");
        return;
    }

    if (n == 0) {
        test_fail(name, "readData returned 0 bytes");
        return;
    }

    // Sanity: at least some bytes should be nonzero.
    int nonzero = 0;
    for (uint32_t i = 0; i < n; i++)
        if (buf[i] != 0) nonzero++;

    if (nonzero == 0) {
        test_fail(name, "all %u bytes are zero", n);
        return;
    }

    printf("         read %u bytes, %d nonzero\n", n, nonzero);
    test_pass(name);
}

static void test_hw_read_multiple(void)
{
    const char *name = "hw_read_multiple";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    struct infnoise_context ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (!initInfnoise(&ctx, NULL, true, false)) {
        test_fail(name, "initInfnoise failed");
        return;
    }

    // Read 10 consecutive batches, verify none fail.
    size_t total = 0;
    for (int i = 0; i < 10; i++) {
        uint8_t buf[BUFLEN];
        uint32_t n = readData(&ctx, buf, false, 1);
        if (ctx.errorFlag) {
            deinitInfnoise(&ctx);
            test_fail(name, "readData error on iteration %d: %s",
                      i, ctx.message ? ctx.message : "unknown");
            return;
        }
        total += n;
    }
    deinitInfnoise(&ctx);

    printf("         10 reads totalling %zu bytes\n", total);
    test_pass(name);
}

/////////////////////////////////////////////
// Layer 2: Provider API tests (EVP_RAND)
/////////////////////////////////////////////

// Helper: load the infnoise provider into a lib context.
// Returns NULL and skips the test if the provider is not available.
static OSSL_PROVIDER *load_infnoise_provider(OSSL_LIB_CTX *libctx,
                                              const char *test_name)
{
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(libctx, "infnoise");
    if (prov == NULL) {
        // Try loading with explicit module path.
        OSSL_PROVIDER_set_default_search_path(libctx,
                                              "/usr/lib/ossl-modules");
        prov = OSSL_PROVIDER_load(libctx, "infnoise");
    }
    if (prov == NULL) {
        test_skip(test_name, "cannot load infnoise provider");
    }
    return prov;
}

static void test_provider_load(void)
{
    const char *name = "provider_load";
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) { OSSL_LIB_CTX_free(libctx); return; }

    // Verify provider name and version.
    const char *pname = OSSL_PROVIDER_get0_name(prov);
    if (pname == NULL || strcmp(pname, "infnoise") != 0) {
        test_fail(name, "provider name is '%s', expected 'infnoise'",
                  pname ? pname : "(null)");
    } else {
        test_pass(name);
    }

    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
}

static void test_provider_params(void)
{
    const char *name = "provider_params";
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) { OSSL_LIB_CTX_free(libctx); return; }

    // Query provider-level params.
    const char *prov_name = NULL;
    const char *prov_version = NULL;
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME,
                                               (char **)&prov_name, 0);
    params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION,
                                               (char **)&prov_version, 0);
    params[2] = OSSL_PARAM_construct_end();

    if (!OSSL_PROVIDER_get_params(prov, params)) {
        test_fail(name, "OSSL_PROVIDER_get_params failed");
    } else if (prov_name == NULL || prov_version == NULL) {
        test_fail(name, "name or version is NULL");
    } else {
        printf("         name='%s' version='%s'\n", prov_name, prov_version);
        test_pass(name);
    }

    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
}

static void test_evp_rand_fetch(void)
{
    const char *name = "evp_rand_fetch";
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) { OSSL_LIB_CTX_free(libctx); return; }

    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    if (rand == NULL) {
        test_fail(name, "EVP_RAND_fetch('infnoise') returned NULL");
    } else {
        const char *rname = EVP_RAND_get0_name(rand);
        const char *rdesc = EVP_RAND_get0_description(rand);
        printf("         fetched: name='%s' desc='%s'\n",
               rname ? rname : "(null)", rdesc ? rdesc : "(null)");
        test_pass(name);
        EVP_RAND_free(rand);
    }

    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
}

static void test_evp_rand_gettable_params_query(void)
{
    const char *name = "evp_rand_gettable_params_query";
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) { OSSL_LIB_CTX_free(libctx); return; }

    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    if (rand == NULL) {
        test_fail(name, "EVP_RAND_fetch failed");
        goto out;
    }

    const OSSL_PARAM *gparams = EVP_RAND_gettable_ctx_params(rand);
    if (gparams == NULL) {
        test_fail(name, "EVP_RAND_gettable_ctx_params returned NULL");
        EVP_RAND_free(rand);
        goto out;
    }

    // Walk the param descriptors and verify we find the expected keys.
    int found_state = 0, found_strength = 0, found_max_req = 0;
    for (const OSSL_PARAM *p = gparams; p->key != NULL; p++) {
        printf("         gettable: key='%s' type=%u\n", p->key, p->data_type);
        if (strcmp(p->key, OSSL_RAND_PARAM_STATE) == 0) found_state = 1;
        if (strcmp(p->key, OSSL_RAND_PARAM_STRENGTH) == 0) found_strength = 1;
        if (strcmp(p->key, OSSL_RAND_PARAM_MAX_REQUEST) == 0) found_max_req = 1;
    }

    EVP_RAND_free(rand);

    if (!found_state || !found_strength || !found_max_req) {
        test_fail(name, "missing expected param (state=%d strength=%d max_req=%d)",
                  found_state, found_strength, found_max_req);
        goto out;
    }

    test_pass(name);

out:
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
}

static void test_evp_rand_ctx_uninitialised(void)
{
    const char *name = "evp_rand_ctx_uninitialised_state";
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) { OSSL_LIB_CTX_free(libctx); return; }

    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    if (rand == NULL) {
        test_fail(name, "EVP_RAND_fetch failed");
        goto out;
    }

    EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) {
        test_fail(name, "EVP_RAND_CTX_new failed");
        EVP_RAND_free(rand);
        goto out;
    }

    // Before instantiate, state should be UNINITIALISED.
    int state = EVP_RAND_get_state(ctx);
    if (state != EVP_RAND_STATE_UNINITIALISED) {
        test_fail(name, "initial state %d != UNINITIALISED(%d)",
                  state, EVP_RAND_STATE_UNINITIALISED);
    } else {
        test_pass(name);
    }

    // Generate should fail when not instantiated.
    unsigned char buf[16];
    ERR_set_mark();
    int ret = EVP_RAND_generate(ctx, buf, sizeof(buf), 0, 0, NULL, 0);
    ERR_pop_to_mark();
    // Just log — don't fail the test on this, since the framework
    // might auto-instantiate in some OpenSSL versions.
    if (ret)
        printf("         note: generate before instantiate returned success "
               "(OpenSSL may auto-instantiate)\n");

    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);

out:
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
}

// Test that multiple provider load/unload cycles don't leak or crash.
static void test_provider_reload(void)
{
    const char *name = "provider_reload_cycles";
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    for (int i = 0; i < 5; i++) {
        OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
        if (prov == NULL) { OSSL_LIB_CTX_free(libctx); return; }

        EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
        if (rand == NULL) {
            test_fail(name, "fetch failed on cycle %d", i);
            OSSL_PROVIDER_unload(prov);
            OSSL_LIB_CTX_free(libctx);
            return;
        }
        EVP_RAND_free(rand);
        OSSL_PROVIDER_unload(prov);
    }

    printf("         5 load/fetch/unload cycles OK\n");
    test_pass(name);
    OSSL_LIB_CTX_free(libctx);
}

static void test_evp_rand_lifecycle(void)
{
    const char *name = "evp_rand_lifecycle";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) {
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    int ok = 1;
    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    EVP_RAND_CTX *ctx = NULL;

    if (rand == NULL) {
        test_fail(name, "EVP_RAND_fetch failed");
        ok = 0;
        goto cleanup;
    }

    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) {
        test_fail(name, "EVP_RAND_CTX_new failed");
        ok = 0;
        goto cleanup;
    }

    // Check state before instantiate.
    int state = EVP_RAND_get_state(ctx);
    if (state != EVP_RAND_STATE_UNINITIALISED) {
        test_fail(name, "initial state %d, expected %d",
                  state, EVP_RAND_STATE_UNINITIALISED);
        ok = 0;
        goto cleanup;
    }

    // Instantiate.
    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL)) {
        test_fail(name, "EVP_RAND_instantiate failed");
        ok = 0;
        goto cleanup;
    }

    state = EVP_RAND_get_state(ctx);
    if (state != EVP_RAND_STATE_READY) {
        test_fail(name, "post-instantiate state %d, expected %d",
                  state, EVP_RAND_STATE_READY);
        ok = 0;
        goto cleanup;
    }

    // Generate some bytes.
    unsigned char buf[64];
    if (!EVP_RAND_generate(ctx, buf, sizeof(buf), 0, 0, NULL, 0)) {
        test_fail(name, "EVP_RAND_generate failed");
        ok = 0;
        goto cleanup;
    }

    // Uninstantiate.
    if (!EVP_RAND_uninstantiate(ctx)) {
        test_fail(name, "EVP_RAND_uninstantiate failed");
        ok = 0;
        goto cleanup;
    }

    state = EVP_RAND_get_state(ctx);
    if (state != EVP_RAND_STATE_UNINITIALISED) {
        test_fail(name, "post-uninstantiate state %d, expected %d",
                  state, EVP_RAND_STATE_UNINITIALISED);
        ok = 0;
        goto cleanup;
    }

cleanup:
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) test_pass(name);
}

static void test_evp_rand_ctx_params(void)
{
    const char *name = "evp_rand_ctx_params";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) {
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    int ok = 1;
    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    EVP_RAND_CTX *ctx = NULL;

    if (rand == NULL) { test_fail(name, "fetch failed"); ok = 0; goto out; }
    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) { test_fail(name, "new ctx failed"); ok = 0; goto out; }
    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL)) {
        test_fail(name, "instantiate failed"); ok = 0; goto out;
    }

    // Read ctx params.
    int state = -1;
    unsigned int strength = 0;
    size_t max_request = 0;
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STATE, &state);
    params[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[2] = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST,
                                             &max_request);
    params[3] = OSSL_PARAM_construct_end();

    if (!EVP_RAND_CTX_get_params(ctx, params)) {
        test_fail(name, "get_ctx_params failed");
        ok = 0;
        goto out;
    }

    printf("         state=%d strength=%u max_request=%zu\n",
           state, strength, max_request);

    if (state != EVP_RAND_STATE_READY) {
        test_fail(name, "state %d != READY(%d)", state, EVP_RAND_STATE_READY);
        ok = 0;
    }
    if (strength != 256) {
        test_fail(name, "strength %u != 256", strength);
        ok = 0;
    }
    if (max_request == 0) {
        test_fail(name, "max_request is 0");
        ok = 0;
    }

out:
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) test_pass(name);
}

static void test_evp_rand_locking(void)
{
    const char *name = "evp_rand_locking";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) {
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    int ok = 1;
    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    EVP_RAND_CTX *ctx = NULL;

    if (rand == NULL) { test_fail(name, "fetch failed"); ok = 0; goto out; }
    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) { test_fail(name, "new ctx failed"); ok = 0; goto out; }

    if (!EVP_RAND_enable_locking(ctx)) {
        test_fail(name, "EVP_RAND_enable_locking failed");
        ok = 0;
        goto out;
    }

    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL)) {
        test_fail(name, "instantiate after enable_locking failed");
        ok = 0;
        goto out;
    }

    unsigned char buf[128];
    if (!EVP_RAND_generate(ctx, buf, sizeof(buf), 0, 0, NULL, 0)) {
        test_fail(name, "generate with locking enabled failed");
        ok = 0;
        goto out;
    }

out:
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) test_pass(name);
}

static void test_evp_rand_strength_check(void)
{
    const char *name = "evp_rand_strength_check";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) {
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    int ok = 1;
    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    EVP_RAND_CTX *ctx = NULL;

    if (rand == NULL) { test_fail(name, "fetch failed"); ok = 0; goto out; }
    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) { test_fail(name, "new ctx failed"); ok = 0; goto out; }

    // Requesting strength > 256 should fail instantiate.
    ERR_set_mark();
    int ret = EVP_RAND_instantiate(ctx, 512, 0, NULL, 0, NULL);
    ERR_pop_to_mark();
    if (ret) {
        test_fail(name, "instantiate with strength=512 should have failed");
        ok = 0;
        goto out;
    }

    // Requesting strength <= 256 should succeed.
    if (!EVP_RAND_instantiate(ctx, 128, 0, NULL, 0, NULL)) {
        test_fail(name, "instantiate with strength=128 failed");
        ok = 0;
        goto out;
    }

    // Generate with strength > 256 should fail.
    unsigned char buf[32];
    ERR_set_mark();
    ret = EVP_RAND_generate(ctx, buf, sizeof(buf), 512, 0, NULL, 0);
    ERR_pop_to_mark();
    if (ret) {
        test_fail(name, "generate with strength=512 should have failed");
        ok = 0;
        goto out;
    }

    // Generate with strength <= 256 should succeed.
    if (!EVP_RAND_generate(ctx, buf, sizeof(buf), 256, 0, NULL, 0)) {
        test_fail(name, "generate with strength=256 failed");
        ok = 0;
        goto out;
    }

out:
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) test_pass(name);
}

static void test_evp_rand_generate_sizes(void)
{
    const char *name = "evp_rand_generate_sizes";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) {
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    int ok = 1;
    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    EVP_RAND_CTX *ctx = NULL;

    if (rand == NULL) { test_fail(name, "fetch failed"); ok = 0; goto out; }
    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) { test_fail(name, "new ctx failed"); ok = 0; goto out; }
    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL)) {
        test_fail(name, "instantiate failed"); ok = 0; goto out;
    }

    // Test a range of sizes: 1, 31, 64, 512, 1024, 4096, 65536.
    static const size_t sizes[] = { 1, 31, 64, 512, 1024, 4096, 65536 };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        unsigned char *buf = malloc(sizes[i]);
        if (buf == NULL) {
            test_fail(name, "malloc(%zu) failed", sizes[i]);
            ok = 0;
            goto out;
        }
        memset(buf, 0xAA, sizes[i]);
        if (!EVP_RAND_generate(ctx, buf, sizes[i], 0, 0, NULL, 0)) {
            test_fail(name, "generate(%zu) failed", sizes[i]);
            free(buf);
            ok = 0;
            goto out;
        }
        // Verify we got non-trivial output (not all 0xAA).
        int changed = 0;
        for (size_t j = 0; j < sizes[i]; j++) {
            if (buf[j] != 0xAA) { changed = 1; break; }
        }
        free(buf);
        if (!changed) {
            test_fail(name, "generate(%zu) did not modify buffer", sizes[i]);
            ok = 0;
            goto out;
        }
    }

    printf("         tested sizes: 1, 31, 64, 512, 1024, 4096, 65536\n");

out:
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) test_pass(name);
}

static void test_evp_rand_reseed(void)
{
    const char *name = "evp_rand_reseed";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) {
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    int ok = 1;
    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    EVP_RAND_CTX *ctx = NULL;

    if (rand == NULL) { test_fail(name, "fetch failed"); ok = 0; goto out; }
    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) { test_fail(name, "new ctx failed"); ok = 0; goto out; }
    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL)) {
        test_fail(name, "instantiate failed"); ok = 0; goto out;
    }

    // Reseed should be a no-op but succeed.
    if (!EVP_RAND_reseed(ctx, 0, NULL, 0, NULL, 0)) {
        test_fail(name, "EVP_RAND_reseed failed");
        ok = 0;
        goto out;
    }

    // Should still generate fine after reseed.
    unsigned char buf[32];
    if (!EVP_RAND_generate(ctx, buf, sizeof(buf), 0, 0, NULL, 0)) {
        test_fail(name, "generate after reseed failed");
        ok = 0;
        goto out;
    }

out:
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) test_pass(name);
}

/////////////////////////////////////////////
// Layer 3: High-level OpenSSL integration
/////////////////////////////////////////////

static void test_rand_bytes(void)
{
    const char *name = "rand_bytes";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    unsigned char buf[256];
    memset(buf, 0, sizeof(buf));

    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        test_fail(name, "RAND_bytes returned failure");
        return;
    }

    // Check not all zeros.
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(buf); i++)
        if (buf[i] != 0) nonzero++;

    if (nonzero == 0) {
        test_fail(name, "RAND_bytes produced all zeros");
        return;
    }

    test_pass(name);
}

static void test_rsa_keygen(void)
{
    const char *name = "rsa_keygen_2048";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;

    if (kctx == NULL) {
        test_fail(name, "EVP_PKEY_CTX_new_id failed");
        return;
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        test_fail(name, "EVP_PKEY_keygen_init failed");
        EVP_PKEY_CTX_free(kctx);
        return;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0) {
        test_fail(name, "set_rsa_keygen_bits failed");
        EVP_PKEY_CTX_free(kctx);
        return;
    }

    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        test_fail(name, "EVP_PKEY_keygen failed");
        EVP_PKEY_CTX_free(kctx);
        return;
    }

    int bits = EVP_PKEY_get_bits(pkey);
    printf("         generated %d-bit RSA key\n", bits);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);

    if (bits != 2048) {
        test_fail(name, "key is %d bits, expected 2048", bits);
        return;
    }
    test_pass(name);
}

static void test_ec_keygen(void)
{
    const char *name = "ec_keygen_p256";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    if (kctx == NULL) {
        test_fail(name, "EVP_PKEY_CTX_new_from_name failed");
        return;
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        test_fail(name, "EVP_PKEY_keygen_init failed");
        EVP_PKEY_CTX_free(kctx);
        return;
    }

    OSSL_PARAM ec_params[2];
    ec_params[0] = OSSL_PARAM_construct_utf8_string("group",
                                                      (char *)"P-256", 0);
    ec_params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(kctx, ec_params) <= 0) {
        test_fail(name, "set_params(group=P-256) failed");
        EVP_PKEY_CTX_free(kctx);
        return;
    }

    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        test_fail(name, "EVP_PKEY_keygen failed");
        EVP_PKEY_CTX_free(kctx);
        return;
    }

    printf("         generated EC P-256 key\n");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    test_pass(name);
}

/////////////////////////////////////////////
// Layer 4: Statistical quality checks
/////////////////////////////////////////////

// Monobit frequency test (NIST SP 800-22, Section 2.1).
// For n bits, compute S = |sum(2*bit_i - 1)|. The p-value is
// erfc(S / sqrt(2*n)). We require p > 0.01.
static void test_stat_monobit(void)
{
    const char *name = "stat_monobit";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    const size_t nbytes = 32768;
    unsigned char *buf = malloc(nbytes);
    if (buf == NULL) { test_fail(name, "malloc failed"); return; }

    if (RAND_bytes(buf, (int)nbytes) != 1) {
        test_fail(name, "RAND_bytes failed");
        free(buf);
        return;
    }

    long sum = 0;
    for (size_t i = 0; i < nbytes; i++) {
        for (int b = 0; b < 8; b++) {
            int bit = (buf[i] >> b) & 1;
            sum += (2 * bit - 1);
        }
    }
    free(buf);

    double n = (double)(nbytes * 8);
    double s_obs = fabs((double)sum) / sqrt(n);
    double p_value = erfc(s_obs / sqrt(2.0));

    printf("         n=%zu bits, |sum|=%ld, s_obs=%.4f, p=%.6f\n",
           (size_t)(nbytes * 8), labs(sum), s_obs, p_value);

    if (p_value < 0.01) {
        test_fail(name, "p-value %.6f < 0.01 (biased output)", p_value);
    } else {
        test_pass(name);
    }
}

// Byte frequency test: chi-squared over 256 bins.
// For n bytes, expected count per bin = n/256.
// chi2 = sum((observed - expected)^2 / expected).
// Degrees of freedom = 255. For p>0.01, chi2 < ~310.
static void test_stat_byte_distribution(void)
{
    const char *name = "stat_byte_distribution";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    const size_t nbytes = 65536;
    unsigned char *buf = malloc(nbytes);
    if (buf == NULL) { test_fail(name, "malloc failed"); return; }

    if (RAND_bytes(buf, (int)nbytes) != 1) {
        test_fail(name, "RAND_bytes failed");
        free(buf);
        return;
    }

    size_t counts[256];
    memset(counts, 0, sizeof(counts));
    for (size_t i = 0; i < nbytes; i++)
        counts[buf[i]]++;
    free(buf);

    double expected = (double)nbytes / 256.0;
    double chi2 = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = (double)counts[i] - expected;
        chi2 += (diff * diff) / expected;
    }

    // df=255, critical value at p=0.001 is ~310.5.
    // Use a generous threshold of 350 to avoid false positives.
    printf("         n=%zu bytes, chi2=%.2f (df=255, threshold<350)\n",
           nbytes, chi2);

    if (chi2 > 350.0) {
        test_fail(name, "chi2=%.2f exceeds threshold (non-uniform)", chi2);
    } else {
        test_pass(name);
    }
}

// Runs test: count runs of consecutive identical bits.
// For truly random data, the expected number of runs is
// 2*n*pi*(1-pi) + 1 where pi = #ones/n.
// We check that the observed runs count is within expected bounds.
static void test_stat_runs(void)
{
    const char *name = "stat_runs";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    const size_t nbytes = 32768;
    unsigned char *buf = malloc(nbytes);
    if (buf == NULL) { test_fail(name, "malloc failed"); return; }

    if (RAND_bytes(buf, (int)nbytes) != 1) {
        test_fail(name, "RAND_bytes failed");
        free(buf);
        return;
    }

    size_t n = nbytes * 8;
    size_t ones = 0;

    // Count ones.
    for (size_t i = 0; i < nbytes; i++) {
        unsigned char byte = buf[i];
        while (byte) { ones += byte & 1; byte >>= 1; }
    }

    // Count runs.
    size_t runs = 1;
    int prev_bit = buf[0] & 1;
    for (size_t i = 0; i < nbytes; i++) {
        int start_bit = (i == 0) ? 1 : 0;
        for (int b = start_bit; b < 8; b++) {
            int bit = (buf[i] >> b) & 1;
            if (bit != prev_bit) runs++;
            prev_bit = bit;
        }
    }
    free(buf);

    double pi = (double)ones / (double)n;
    double expected_runs = 2.0 * (double)n * pi * (1.0 - pi) + 1.0;
    double denom = 2.0 * sqrt(2.0 * (double)n) * pi * (1.0 - pi);
    double z = fabs((double)runs - expected_runs) / denom;
    double p_value = erfc(z / sqrt(2.0));

    printf("         n=%zu bits, ones=%zu (pi=%.4f), runs=%zu, p=%.6f\n",
           n, ones, pi, runs, p_value);

    if (p_value < 0.01) {
        test_fail(name, "p-value %.6f < 0.01 (non-random runs)", p_value);
    } else {
        test_pass(name);
    }
}

// Two-sample independence test: generate two separate blocks and verify
// they are not identical (would indicate a stuck or replaying source).
static void test_stat_two_sample(void)
{
    const char *name = "stat_two_sample_independence";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    unsigned char buf1[4096], buf2[4096];

    if (RAND_bytes(buf1, sizeof(buf1)) != 1 ||
        RAND_bytes(buf2, sizeof(buf2)) != 1) {
        test_fail(name, "RAND_bytes failed");
        return;
    }

    if (memcmp(buf1, buf2, sizeof(buf1)) == 0) {
        test_fail(name, "two 4096-byte samples are identical");
        return;
    }

    // Also verify they differ in a significant number of bytes.
    int diff_count = 0;
    for (size_t i = 0; i < sizeof(buf1); i++)
        if (buf1[i] != buf2[i]) diff_count++;

    double diff_pct = 100.0 * (double)diff_count / (double)sizeof(buf1);
    printf("         samples differ in %d/%zu bytes (%.1f%%)\n",
           diff_count, sizeof(buf1), diff_pct);

    // For truly random data, ~99.6% of bytes should differ.
    // Be generous: require at least 90%.
    if (diff_pct < 90.0) {
        test_fail(name, "only %.1f%% bytes differ (expected >90%%)", diff_pct);
    } else {
        test_pass(name);
    }
}

/////////////////////////////////////////////
// Layer 5: Memory safety and robustness
/////////////////////////////////////////////

// Rapid create/destroy cycles to detect leaks under ASan.
static void test_mem_ctx_churn(void)
{
    const char *name = "mem_ctx_churn";
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) { OSSL_LIB_CTX_free(libctx); return; }

    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    if (rand == NULL) {
        test_fail(name, "EVP_RAND_fetch failed");
        OSSL_PROVIDER_unload(prov);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    // 100 cycles of newctx/freectx without instantiate.
    for (int i = 0; i < 100; i++) {
        EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(rand, NULL);
        if (ctx == NULL) {
            test_fail(name, "EVP_RAND_CTX_new failed on iteration %d", i);
            EVP_RAND_free(rand);
            OSSL_PROVIDER_unload(prov);
            OSSL_LIB_CTX_free(libctx);
            return;
        }
        EVP_RAND_CTX_free(ctx);
    }

    printf("         100 newctx/freectx cycles OK\n");
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    test_pass(name);
}

// Instantiate/generate/uninstantiate cycles to detect leaks in the
// TRNG init/deinit path.
static void test_mem_instantiate_churn(void)
{
    const char *name = "mem_instantiate_churn";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) {
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    if (rand == NULL) {
        test_fail(name, "EVP_RAND_fetch failed");
        goto out;
    }

    for (int i = 0; i < 10; i++) {
        EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(rand, NULL);
        if (ctx == NULL) {
            test_fail(name, "newctx failed on cycle %d", i);
            EVP_RAND_free(rand);
            goto out;
        }

        if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL)) {
            test_fail(name, "instantiate failed on cycle %d", i);
            EVP_RAND_CTX_free(ctx);
            EVP_RAND_free(rand);
            goto out;
        }

        unsigned char buf[64];
        if (!EVP_RAND_generate(ctx, buf, sizeof(buf), 0, 0, NULL, 0)) {
            test_fail(name, "generate failed on cycle %d", i);
            EVP_RAND_CTX_free(ctx);
            EVP_RAND_free(rand);
            goto out;
        }

        if (!EVP_RAND_uninstantiate(ctx)) {
            test_fail(name, "uninstantiate failed on cycle %d", i);
            EVP_RAND_CTX_free(ctx);
            EVP_RAND_free(rand);
            goto out;
        }

        EVP_RAND_CTX_free(ctx);
    }

    printf("         10 instantiate/generate/uninstantiate/free cycles OK\n");
    EVP_RAND_free(rand);
    test_pass(name);

out:
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);
}

// Verify that generate on a large boundary-crossing size works without
// buffer overflow (ring buffer wraps).
static void test_mem_boundary_generate(void)
{
    const char *name = "mem_boundary_generate";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) {
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    int ok = 1;
    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    EVP_RAND_CTX *ctx = NULL;
    if (rand == NULL) { test_fail(name, "fetch failed"); ok = 0; goto out; }
    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) { test_fail(name, "new ctx failed"); ok = 0; goto out; }
    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL)) {
        test_fail(name, "instantiate failed"); ok = 0; goto out;
    }

    // Request sizes that cross ring buffer boundaries:
    // BUFLEN=512, ring=1024. Sizes: 1, 511, 512, 513, 1023, 1024, 1025, 2048.
    static const size_t sizes[] = { 1, 511, 512, 513, 1023, 1024, 1025, 2048 };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        unsigned char *buf = calloc(sizes[i] + 16, 1);  // + canary
        if (buf == NULL) {
            test_fail(name, "calloc(%zu) failed", sizes[i] + 16);
            ok = 0;
            goto out;
        }

        // Set canary bytes after the buffer region.
        memset(buf + sizes[i], 0xDE, 16);

        if (!EVP_RAND_generate(ctx, buf, sizes[i], 0, 0, NULL, 0)) {
            test_fail(name, "generate(%zu) failed", sizes[i]);
            free(buf);
            ok = 0;
            goto out;
        }

        // Verify canary is intact (no buffer overflow).
        int canary_ok = 1;
        for (int j = 0; j < 16; j++) {
            if (buf[sizes[i] + j] != 0xDE) { canary_ok = 0; break; }
        }
        free(buf);

        if (!canary_ok) {
            test_fail(name, "canary corrupted after generate(%zu) - "
                      "buffer overflow!", sizes[i]);
            ok = 0;
            goto out;
        }
    }

    printf("         boundary sizes 1,511,512,513,1023,1024,1025,2048 OK\n");

out:
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) test_pass(name);
}

// Verify that generating a zero-length request succeeds without issue.
static void test_mem_zero_length_generate(void)
{
    const char *name = "mem_zero_length_generate";
    if (!hw_detected) { test_skip(name, "no hardware"); return; }

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) { test_fail(name, "OSSL_LIB_CTX_new failed"); return; }

    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov = load_infnoise_provider(libctx, name);
    if (prov == NULL) {
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(libctx);
        return;
    }

    int ok = 1;
    EVP_RAND *rand = EVP_RAND_fetch(libctx, "infnoise", NULL);
    EVP_RAND_CTX *ctx = NULL;
    if (rand == NULL) { test_fail(name, "fetch failed"); ok = 0; goto out; }
    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) { test_fail(name, "new ctx failed"); ok = 0; goto out; }
    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL)) {
        test_fail(name, "instantiate failed"); ok = 0; goto out;
    }

    unsigned char buf[1] = { 0xAA };
    if (!EVP_RAND_generate(ctx, buf, 0, 0, 0, NULL, 0)) {
        test_fail(name, "generate(0) failed");
        ok = 0;
        goto out;
    }

    // Buffer should be untouched.
    if (buf[0] != 0xAA) {
        test_fail(name, "buffer modified by zero-length generate");
        ok = 0;
    }

out:
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(libctx);
    if (ok) test_pass(name);
}

///////////////////////
// Main
///////////////////////

int main(void)
{
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    printf(CLR_BOLD "Infinite Noise TRNG Provider Test Harness" CLR_RESET "\n");
    printf("OpenSSL %s\n", OpenSSL_version(OPENSSL_VERSION));

    section("Layer 1: Direct libinfnoise hardware tests");
    test_hw_detect();
    test_hw_init_deinit();
    test_hw_read_raw();
    test_hw_read_multiple();

    section("Layer 2a: Provider API tests (no hardware needed)");
    test_provider_load();
    test_provider_params();
    test_evp_rand_fetch();
    test_evp_rand_gettable_params_query();
    test_evp_rand_ctx_uninitialised();
    test_provider_reload();

    section("Layer 2b: Provider API tests (hardware required)");
    test_evp_rand_lifecycle();
    test_evp_rand_ctx_params();
    test_evp_rand_locking();
    test_evp_rand_strength_check();
    test_evp_rand_generate_sizes();
    test_evp_rand_reseed();

    section("Layer 3: High-level OpenSSL integration");
    test_rand_bytes();
    test_rsa_keygen();
    test_ec_keygen();

    section("Layer 4: Statistical quality");
    test_stat_monobit();
    test_stat_byte_distribution();
    test_stat_runs();
    test_stat_two_sample();

    section("Layer 5: Memory safety and robustness");
    test_mem_ctx_churn();
    test_mem_instantiate_churn();
    test_mem_boundary_generate();
    test_mem_zero_length_generate();

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (double)(end.tv_sec - start.tv_sec)
                   + (double)(end.tv_nsec - start.tv_nsec) / 1e9;

    printf("\n" CLR_BOLD "========================================" CLR_RESET "\n");
    printf(CLR_BOLD "Test Summary" CLR_RESET "\n");
    printf("  Total:   %d\n", tests_run);
    printf("  " CLR_GREEN "Passed:  %d" CLR_RESET "\n", tests_passed);
    if (tests_failed > 0)
        printf("  " CLR_RED "Failed:  %d" CLR_RESET "\n", tests_failed);
    else
        printf("  Failed:  %d\n", tests_failed);
    if (tests_skipped > 0)
        printf("  " CLR_YELLOW "Skipped: %d" CLR_RESET "\n", tests_skipped);
    else
        printf("  Skipped: %d\n", tests_skipped);
    printf("  Time:    %.2fs\n", elapsed);
    if (!hw_detected)
        printf("\n  " CLR_YELLOW "NOTE: No Infinite Noise TRNG hardware "
               "detected.\n  Hardware-dependent tests were skipped."
               CLR_RESET "\n");
    printf(CLR_BOLD "========================================" CLR_RESET "\n");

    return tests_failed > 0 ? 1 : 0;
}
