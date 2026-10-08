#ifndef CONTOUR_ABI_V1_H
#define CONTOUR_ABI_V1_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum contour_status {
    CONTOUR_OK = 0,
    CONTOUR_ARGUMENT = 1,
    CONTOUR_INPUT = 2,
    CONTOUR_CAPACITY = 3,
    CONTOUR_INTERNAL = 4
};
typedef struct contour_result {
    uint32_t status;
    size_t canonical_length;
    size_t fingerprint_length;
} contour_result;

/* Input: structure-only UTF-8 JSON, at most 65536 bytes. Output is not NUL
 * terminated. The fingerprint is 64 lowercase hexadecimal bytes.
 * The caller owns live readable input and writable output memory for the full
 * stated lengths/capacities. Regions must be disjoint and exclusively accessed
 * for this call. Native pointer validity cannot be checked by this interface.
 * Null output + zero capacity requests sizes. No buffer is changed on failure.
 * CAPACITY reports both required lengths; other errors report zero lengths.
 * Oversized input is rejected before any pointer is dereferenced.
 * Never free these caller-owned buffers through a Rust allocator.
 */
contour_result contour_shape_v1(const uint8_t *input, size_t input_length,
    uint8_t *canonical, size_t canonical_capacity,
    uint8_t *fingerprint, size_t fingerprint_capacity);

#ifdef __cplusplus
}
#endif
#endif
