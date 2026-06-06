/* Tiny test harness — no external deps. */
#ifndef GSA_TEST_UTIL_H
#define GSA_TEST_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_tests_run = 0;
static int g_tests_failed = 0;

static inline void hex2bin(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        unsigned v = 0;
        sscanf(hex + i * 2, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static inline void print_hex(const char *label, const uint8_t *b, size_t n) {
    fprintf(stderr, "  %s: ", label);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
}

#define CHECK_EQ_BYTES(name, got, want, len)                                   \
    do {                                                                       \
        g_tests_run++;                                                         \
        if (memcmp((got), (want), (len)) != 0) {                               \
            g_tests_failed++;                                                   \
            fprintf(stderr, "FAIL: %s\n", (name));                             \
            print_hex("got ", (const uint8_t *)(got), (len));                  \
            print_hex("want", (const uint8_t *)(want), (len));                 \
        } else {                                                               \
            fprintf(stderr, "ok:   %s\n", (name));                             \
        }                                                                      \
    } while (0)

#define CHECK_TRUE(name, cond)                                                 \
    do {                                                                       \
        g_tests_run++;                                                         \
        if (!(cond)) {                                                         \
            g_tests_failed++;                                                   \
            fprintf(stderr, "FAIL: %s\n", (name));                             \
        } else {                                                               \
            fprintf(stderr, "ok:   %s\n", (name));                             \
        }                                                                      \
    } while (0)

#define SKIP(name, why)                                                        \
    fprintf(stderr, "skip: %s (%s)\n", (name), (why))

#define TEST_SUMMARY()                                                         \
    (fprintf(stderr, "\n%d run, %d failed\n", g_tests_run, g_tests_failed),    \
     g_tests_failed == 0 ? 0 : 1)

#endif /* GSA_TEST_UTIL_H */
