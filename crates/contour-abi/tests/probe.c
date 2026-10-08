#include "contour.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t input[65537];
static struct { uint8_t before[16], bytes[65536], after[16]; } canonical_guard;
static struct { uint8_t before[16], bytes[64], after[16]; } fingerprint_guard;
#define canonical canonical_guard.bytes
#define fingerprint fingerprint_guard.bytes
#define REQUIRE(test) do { if (!(test)) { \
    fprintf(stderr, "ABI boundary assertion failed at line %d\n", __LINE__); return 1; \
} } while (0)

static int untouched(void) {
    for (size_t i = 0; i < sizeof canonical; ++i)
        if (canonical[i] != 0xa5) return 0;
    for (size_t i = 0; i < sizeof fingerprint; ++i)
        if (fingerprint[i] != 0x5a) return 0;
    return 1;
}
static int guards(void) {
    for (size_t i = 0; i < 16; ++i)
        if (canonical_guard.before[i] != 0xa5 || canonical_guard.after[i] != 0xa5
            || fingerprint_guard.before[i] != 0x5a || fingerprint_guard.after[i] != 0x5a)
            return 0;
    return 1;
}
static void reset(void) {
    memset(&canonical_guard, 0xa5, sizeof canonical_guard);
    memset(&fingerprint_guard, 0x5a, sizeof fingerprint_guard);
}
static int boundaries(void) {
    const uint8_t valid[] = "{\"kind\":\"string\"}";
    const size_t length = sizeof valid - 1;
    reset();
    contour_result r = contour_shape_v1(valid, length, NULL, 0, NULL, 0);
    REQUIRE(r.status == CONTOUR_CAPACITY && r.canonical_length == 10
            && r.fingerprint_length == 64 && untouched());
    r = contour_shape_v1(valid, length, canonical, 9, fingerprint, 64);
    REQUIRE(r.status == CONTOUR_CAPACITY && r.canonical_length == 10
            && r.fingerprint_length == 64 && untouched());
    r = contour_shape_v1(valid, length, canonical, sizeof canonical, fingerprint, 63);
    REQUIRE(r.status == CONTOUR_CAPACITY && untouched());
    r = contour_shape_v1(NULL, 0, canonical, sizeof canonical, fingerprint, 64);
    REQUIRE(r.status == CONTOUR_ARGUMENT && r.canonical_length == 0 && untouched());
    r = contour_shape_v1(valid, 0, canonical, sizeof canonical, fingerprint, 64);
    REQUIRE(r.status == CONTOUR_INPUT && r.fingerprint_length == 0 && untouched());
    r = contour_shape_v1(NULL, 65537, NULL, 0, NULL, 0);
    REQUIRE(r.status == CONTOUR_INPUT && untouched());
    r = contour_shape_v1(valid, length, NULL, 10, fingerprint, 64);
    REQUIRE(r.status == CONTOUR_ARGUMENT && untouched());
    r = contour_shape_v1(valid, length, canonical, sizeof canonical, NULL, 64);
    REQUIRE(r.status == CONTOUR_ARGUMENT && untouched());
    r = contour_shape_v1(valid, length, canonical, sizeof canonical, canonical + 1, 64);
    REQUIRE(r.status == CONTOUR_ARGUMENT && untouched());
    r = contour_shape_v1((const uint8_t *)(UINTPTR_MAX - 3), length,
                         canonical, sizeof canonical, fingerprint, 64);
    REQUIRE(r.status == CONTOUR_ARGUMENT && untouched());
    r = contour_shape_v1(valid, length, (uint8_t *)(UINTPTR_MAX - 3), 10,
                         fingerprint, 64);
    REQUIRE(r.status == CONTOUR_ARGUMENT && untouched() && guards());
    memcpy(input, valid, length);
    r = contour_shape_v1(input, length, input, sizeof input, fingerprint, 64);
    REQUIRE(r.status == CONTOUR_ARGUMENT && memcmp(input, valid, length) == 0 && untouched());
    r = contour_shape_v1(valid, length, canonical, sizeof canonical, fingerprint, 64);
    REQUIRE(r.status == CONTOUR_OK && r.canonical_length == 10
            && r.fingerprint_length == 64 && memcmp(canonical, "[\"string\"]", 10) == 0
            && guards());
    for (size_t i = 10; i < sizeof canonical; ++i) REQUIRE(canonical[i] == 0xa5);
    puts("C ABI pointer, capacity and guard checks passed");
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--boundaries") == 0) return boundaries();
    if (argc != 1) return 2;
    size_t length = fread(input, 1, sizeof input, stdin);
    if (ferror(stdin) || (length == sizeof input && fgetc(stdin) != EOF)) return 2;
    reset();
    contour_result r = contour_shape_v1(input, length, canonical, sizeof canonical,
                                      fingerprint, sizeof fingerprint);
    if (r.status != CONTOUR_OK) {
        REQUIRE(r.canonical_length == 0 && r.fingerprint_length == 0 && untouched() && guards());
        printf("%u\n", (unsigned) r.status);
        return 0;
    }
    REQUIRE(r.canonical_length <= sizeof canonical && r.fingerprint_length == 64 && guards());
    for (size_t i = r.canonical_length; i < sizeof canonical; ++i)
        REQUIRE(canonical[i] == 0xa5);
    printf("0\n");
    if (fwrite(fingerprint, 1, 64, stdout) != 64 || putchar('\n') == EOF
        || fwrite(canonical, 1, r.canonical_length, stdout) != r.canonical_length) return 2;
    return 0;
}
