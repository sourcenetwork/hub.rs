#ifndef VERA_VERIFIER_H
#define VERA_VERIFIER_H
#include <stddef.h>
#include <stdint.h>
typedef struct { uint8_t *data; size_t len; } VeraBuffer;
/* Input remains caller-owned; output must be freed exactly once. */
VeraBuffer vera_verify(const uint8_t *input, size_t len);
void vera_buffer_free(VeraBuffer buffer);
#endif
