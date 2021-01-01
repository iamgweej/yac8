#include <stdlib.h>

#include "opcodes.h"

void disassemble(const opcode_t *ops, size_t length, size_t offset, FILE *f)
{
    opcode_t op = 0;

    if (SIZE_MAX == length)
    {
        // TODO: Error handling
        return;
    }

    for (size_t i = 0; i < length; i++)
    {
        op = ops[i];

        printf(
            "%04llx\t%02x %02x\t",
            i * sizeof(opcode_t) + offset,
            op & 0xff,
            0xff & ((op) >> 8));

        format_opcode(f, op);
        fputc('\n', f);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [chip8-file]\n", argv[0]);
        return 1;
    }

    FILE *f = NULL;
    if (0 != fopen_s(&f, argv[1], "rb"))
    {
        fprintf(stderr, "Couldnt open %s: ", argv[1]);
        perror(NULL);
        return 2;
    }

    contextp_t context = create_context(f);
    fclose(f);
    if (NULL == context)
    {
        perror("create_context failed: ");
        return 4;
    }

    // disassemble((opcode_t *)buf, fsize, 0x200, stdout);
    // free(buf);

    int err;
    do 
    {
        chip8_trace(context, stdout);
        printf("\n");
    } while (!(err = step(context)));
    printf("Error: %s (%d)\n", chip8_err_str(err), err);
    chip8_trace(context, stdout);
    destroy_context(context);
    return 0;
}
