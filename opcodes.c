#include "opcodes.h"

#define GET_ADDR(op) ((op >> 8) | ((op & 0x0f) << 8))
#define GET_NIBBLE(op) ((op >> 8) & 0x0f)
#define GET_X(op) (op & 0x0f)
#define GET_Y(op) ((op & 0xf000) >> 12)
#define GET_BYTE(op) (op >> 8)

#define GET_MASK(opconf)                \
    (0xffff ^                           \
     (opconf.has_addr ? 0xff0f : 0) ^   \
     (opconf.has_nibble ? 0x0f00 : 0) ^ \
     (opconf.has_x ? 0x000f : 0) ^      \
     (opconf.has_y ? 0xf000 : 0) ^      \
     (opconf.has_byte ? 0xff00 : 0))
#define OP_MATCH(opconf, op) ((GET_MASK(opconf) & (opcode)) == (opconf).filter)

// X(mnemonic, filter, addr, nibble, x, y, byte)
#define OPCODES_LIST               \
    X(cls, 0x00E0, 0, 0, 0, 0, 0)  \
    X(ret, 0x00EE, 0, 0, 0, 0, 0)  \
    X(jpa, 0x1000, 1, 0, 0, 0, 0)  \
    X(call, 0x2000, 1, 0, 0, 0, 0) \
    X(sei, 0x3000, 0, 0, 1, 0, 1)  \
    X(snei, 0x4000, 0, 0, 1, 0, 1) \
    X(se, 0x5000, 0, 0, 1, 1, 0)   \
    X(ldi, 0x6000, 0, 0, 1, 0, 1)  \
    X(addi, 0x7000, 0, 0, 1, 0, 1) \
    X(ld, 0x8000, 0, 0, 1, 1, 0)   \
    X(or, 0x8001, 0, 0, 1, 1, 0)   \
    X(and, 0x8002, 0, 0, 1, 1, 0)  \
    X(xor, 0x8003, 0, 0, 1, 1, 0)  \
    X(add, 0x8004, 0, 0, 1, 1, 0)  \
    X(sub, 0x8005, 0, 0, 1, 1, 0)  \
    X(shr, 0x8006, 0, 0, 1, 1, 0)  \
    X(subn, 0x8007, 0, 0, 1, 1, 0) \
    X(shl, 0x800E, 0, 0, 1, 1, 0)  \
    X(sne, 0x9000, 0, 0, 1, 1, 0)  \
    X(lda, 0xA000, 1, 0, 0, 0, 0)  \
    X(jp0, 0xB000, 1, 0, 0, 0, 0)  \
    X(rnd, 0xC000, 0, 0, 0, 0, 1)  \
    X(drw, 0xD000, 0, 1, 1, 1, 0)  \
    X(skp, 0xE09E, 0, 0, 1, 0, 0)  \
    X(sknp, 0xE0A1, 0, 0, 1, 0, 0) \
    X(lddt, 0xF007, 0, 0, 1, 0, 0) \
    X(stkp, 0xF00A, 0, 0, 1, 0, 0) \
    X(stdt, 0xF015, 0, 0, 1, 0, 0) \
    X(stst, 0xF018, 0, 0, 1, 0, 0) \
    X(adda, 0xF01E, 0, 0, 1, 0, 0) \
    X(lds, 0xF029, 0, 0, 1, 0, 0)  \
    X(bcd, 0xF033, 0, 0, 1, 0, 0)  \
    X(str, 0xF055, 0, 0, 1, 0, 0)  \
    X(ldr, 0XF065, 0, 0, 1, 0, 0)  \
    X(sys, 0x0000, 1, 0, 0, 0, 0)

#define OPCODE_ENUM_NAME(mnemonic) CHIP8_OP_##mnemonic

enum Chip8Opcodes
{
#define X(mnemonic, ...) OPCODE_ENUM_NAME(mnemonic),
    OPCODES_LIST
#undef X
    OPCODE_ENUM_NAME(OPCODE_MAX)
};

#define APPLY_FUNC_NAME(mnemonic) apply_ ## mnemonic

#define OP_APPLY_PROTO_00000(mnemonic) int APPLY_FUNC_NAME(mnemonic) (contextp_t context);
#define OP_APPLY_PROTO_10000(mnemonic) int APPLY_FUNC_NAME(mnemonic) (contextp_t context, uint16_t addr);
#define OP_APPLY_PROTO_00100(mnemonic) int APPLY_FUNC_NAME(mnemonic) (contextp_t context, uint8_t x);
#define OP_APPLY_PROTO_00110(mnemonic) int APPLY_FUNC_NAME(mnemonic) (contextp_t context, uint8_t x, uint8_t y);
#define OP_APPLY_PROTO_01110(mnemonic) int APPLY_FUNC_NAME(mnemonic) (contextp_t context, uint8_t x, uint8_t y, uint8_t n);
#define OP_APPLY_PROTO_00101(mnemonic) int APPLY_FUNC_NAME(mnemonic) (contextp_t context, uint8_t x, uint8_t byte);
#define OP_APPLY_PROTO_00001(mnemonic) int APPLY_FUNC_NAME(mnemonic) (contextp_t context, uint8_t byte);

#define X(mnemonic, filter, addr, nibble, x, y, byte) OP_APPLY_PROTO_ ## addr ## nibble ## x ## y ## byte (mnemonic)
OPCODES_LIST
#undef X

typedef struct _context
{
    uint8_t ram[0x1000];
    uint8_t v[0x10];
    uint16_t i;
    uint8_t dt;
    uint8_t st;
    uint16_t pc;
    uint8_t sp;
    uint16_t stack[0x10];
} context_t;

typedef int (*none_op_f)(context_t *c);
typedef int (*nnn_op_f)(context_t *c, uint16_t addr);
typedef int (*x_op_f)(context_t *c, uint8_t x);
typedef int (*xy_op_f)(context_t *c, uint8_t x, uint8_t y);
typedef int (*xyn_op_f)(context_t *c, uint8_t x, uint8_t y, uint8_t n);
typedef int (*xkk_op_f)(context_t *c, uint8_t x, uint8_t byte);

typedef struct
{
    uint16_t filter;
    uint8_t has_addr : 1;
    uint8_t has_nibble : 1;
    uint8_t has_x : 1;
    uint8_t has_y : 1;
    uint8_t has_byte : 1;
    const char *mnemonic;
    union
    {
        none_op_f f_none;
        nnn_op_f f_nnn;
        x_op_f f_x;
        xy_op_f f_xy;
        xyn_op_f f_xyn;
        xkk_op_f f_xkk;
        void *raw;
    } u;
} opcode_config_t;

static opcode_config_t opconfs[] = {
#define X(mnemonic_, code, addr, nibble, x, y, byte) \
    [OPCODE_ENUM_NAME(mnemonic_)] = {                \
        .filter = MAKE_OPCODE(code),                 \
        .has_addr = addr,                            \
        .has_nibble = nibble,                        \
        .has_x = x,                                  \
        .has_y = y,                                  \
        .has_byte = byte,                            \
        .mnemonic = #mnemonic_,                      \
        .u = NULL,                                   \
    },
    OPCODES_LIST
#undef X
};

void format_opcode(FILE *f, opcode_t opcode)
{
    for (int i = 0; i < ARR_LEN(opconfs); i++)
    {
        if (OP_MATCH(opconfs[i], opcode))
        {
            fprintf(f, "%s", opconfs[i].mnemonic);
            if (opconfs[i].has_addr)
            {
                printf("\t%03x", GET_ADDR(opcode));
            }
            else if (opconfs[i].has_x)
            {
                printf("\tV%x", GET_X(opcode));
                if (opconfs[i].has_y)
                {
                    printf(", V%x", GET_Y(opcode));
                    if (opconfs[i].has_nibble)
                    {
                        printf(", %x", GET_NIBBLE(opcode));
                    }
                }
                else if (opconfs[i].has_byte)
                {
                    printf(", %02x", GET_BYTE(opcode));
                }
            }
            return;
        }
    }
    fprintf(f, "(bad)");
}

#define CHIP8_ERRORS                                             \
    Y(OK, "No error")                                            \
    Y(ILL, "Illegal instruction")                                \
    Y(SP_UF, "A `ret` was issued when the call stack was empty") \
    Y(SP_OF, "A `call` was issued when the call stack was full") \
    Y(NI, "This opcode is not yet implemented")

#define ERROR_ENUM_NAME(abbr) CHIP8_ERROR_##abbr

enum Chip8Errors
{
#define Y(abbr, ...) ERROR_ENUM_NAME(abbr),
    CHIP8_ERRORS
#undef Y
};

static const char *error_strings[] = {
#define Y(abbr, str) [ERROR_ENUM_NAME(abbr)] = str,
    CHIP8_ERRORS
#undef Y
};

const char *chip8_err_str(int err)
{
    if (err >= sizeof(error_strings) || err < 0)
    {
        return "No such error.";
    }
    return error_strings[err];
}

static inline int dispatch(opcode_config_t opconf, opcode_t opcode, context_t *c)
{
    if (NULL == opconf.u.raw)
    {
        return ERROR_ENUM_NAME(NI);
    }
    if (opconf.has_addr)
    {
        return opconf.u.f_nnn(c, GET_ADDR(opcode));
    }
    if (opconf.has_byte)
    {
        return opconf.u.f_xkk(c, GET_X(opcode), GET_BYTE(opcode));
    }
    if (opconf.has_nibble)
    {
        return opconf.u.f_xyn(c, GET_X(opcode), GET_Y(opcode), GET_NIBBLE(opcode));
    }
    if (opconf.has_y)
    {
        return opconf.u.f_xy(c, GET_X(opcode), GET_Y(opcode));
    }
    if (opconf.has_x)
    {
        return opconf.u.f_x(c, GET_X(opcode));
    }
    return opconf.u.f_none(c);
}

int step(context_t *c)
{
    opcode_t opcode = *(opcode_t *)(c->ram + c->pc);
    int ret = 0;
    for (int i = 0; i < ARR_LEN(opconfs); i++)
    {
        if (OP_MATCH(opconfs[i], opcode))
        {
            ret = dispatch(opconfs[i], opcode, c);
            if (ret) {
                return ret;
            }

            c->pc += 2;
            return ERROR_ENUM_NAME(OK);
        }
    }
    // TODO: constants or enum
    return ERROR_ENUM_NAME(ILL);
}

static void disassemble_at(context_t *c, uint16_t pc, FILE *f)
{
    opcode_t op = *(opcode_t *)(c->ram + pc);
    fprintf(f, "%04x\t%02x %02x\t", pc, op & 0xff, (op >> 8));
    format_opcode(f, op);
}

static void disassemble_around(context_t *c, uint16_t pc, int around, FILE *f)
{
    uint16_t lower = max(around * sizeof(opcode_t), pc) - around * sizeof(opcode_t);
    uint16_t upper = min(0x1000 - (around + 1) * sizeof(opcode_t), pc) + (around + 1) * sizeof(opcode_t);
    uint16_t i;
    for (i = lower; i < pc; i += sizeof(opcode_t))
    {
        disassemble_at(c, i, f);
        fputc('\n', f);
    }
    disassemble_at(c, pc, f);
    fputs("\t<---\n", f);
    for (i = pc + sizeof(opcode_t); i < upper; i += sizeof(opcode_t))
    {
        disassemble_at(c, i, f);
        fputc('\n', f);
    }
}

void chip8_trace(context_t *c, FILE *f)
{
    disassemble_around(c, c->pc, 3, f);
}

int apply_call(context_t *c, uint16_t addr)
{
    if (0x10 == c->sp) {
        return ERROR_ENUM_NAME(SP_OF);
    }
    c->stack[c->sp++] = c->pc + 2;
    c->pc = addr - 2;
    return ERROR_ENUM_NAME(OK);
}

int apply_ret(context_t *c)
{
    if (0 == c->sp) {
        return ERROR_ENUM_NAME(SP_UF);
    }
    c->pc = c->stack[--c->sp] - 2;
    return ERROR_ENUM_NAME(OK);
}

int apply_addi(context_t *c, uint8_t x, uint8_t byte) {
    c->v[x] += byte;
    return ERROR_ENUM_NAME(OK);
}

int apply_lda(context_t *c, uint16_t addr)
{
    c->i = addr;
    return ERROR_ENUM_NAME(OK);
}

int apply_ldi(context_t *c, uint8_t x, uint8_t byte)
{
    c->v[x] = byte;
    return ERROR_ENUM_NAME(OK);
}

int apply_sei(context_t *c, uint8_t x, uint8_t byte)
{
    if (c->v[x] == byte)
    {
        c->pc += 2;
    }
    return ERROR_ENUM_NAME(OK);
}

context_t *create_context(FILE *f)
{

    context_t *c = malloc(sizeof(context_t));
    if (NULL == c)
    {
        return NULL;
    }

    memset(c, 0, sizeof(*c));

    fread(c->ram + 0x200, sizeof(c->ram) - 0x200, 1, f);
    c->pc = 0x200;

    // TODO: This will move.
    opconfs[OPCODE_ENUM_NAME(lda)].u.raw = apply_lda;
    opconfs[OPCODE_ENUM_NAME(call)].u.raw = apply_call;
    opconfs[OPCODE_ENUM_NAME(ldi)].u.raw = apply_ldi;
    opconfs[OPCODE_ENUM_NAME(sei)].u.raw = apply_sei;
    opconfs[OPCODE_ENUM_NAME(ret)].u.raw = apply_ret;
    opconfs[OPCODE_ENUM_NAME(addi)].u.raw = apply_addi;

    return c;
}

void destroy_context(context_t *c)
{
    free(c);
}
