#include "wsc.h"
#include <stdio.h>

#define TEST_PASS 0
#define TEST_FAIL 1

int run_test(const char *name, int (*test_func)(void)) {
    int result = test_func();
    if (result == TEST_PASS) {
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
    }
    return result;
}

int test_client_init(void) {
    wsc_client_t client = { .host = "127.0.0.1", .port = 9001 };
    if (wsc_client_init(&client) != 0) {
        return TEST_FAIL;
    }
    wsc_client_deinit(&client);
    return TEST_PASS;
}

int test_handshake(void) {
    wsc_client_t client = { .host = "127.0.0.1", .port = 9001 };
    if (wsc_client_init(&client) != 0) return TEST_FAIL;

    if (wsc_handshake(&client, "/") != 0) {
        wsc_client_deinit(&client);
        return TEST_FAIL;
    }

    wsc_client_deinit(&client);
    return TEST_PASS;
}

int main(void) {
    int failures = 0;

    failures += run_test("Client Initialization", test_client_init);
    failures += run_test("WebSocket Handshake", test_handshake);

    if (failures == 0) {
        printf("\nAll tests passed\n");
        return 0;
    } else {
        printf("\n%d test(s) failed\n", failures);
        return 1;
    }
}

