#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#define MAKE_OPCODE(x) ((x >> 8) | ((x & 0xff) << 8))

#define ARR_LEN(a) (sizeof(a) / sizeof(a[0]))

typedef uint16_t opcode_t;
typedef struct _context* contextp_t;

void format_opcode(FILE *f, opcode_t opcode);

int step(contextp_t c);

contextp_t create_context(FILE *f);
void destroy_context(contextp_t c);

void chip8_trace(contextp_t c, FILE* f);
const char* chip8_err_str(int err);