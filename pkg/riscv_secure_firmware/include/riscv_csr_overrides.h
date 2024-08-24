#pragma once

#include <string.h>

#include "panic.h"
#include "macros/xtstr.h"

#include "vendor/riscv_csr.h"

#include "uapi/interrupt.h"
#include "uapi/ecall.h"


#undef read_csr
#undef write_csr
#undef swap_csr
#undef set_csr
#undef clear_csr

extern volatile int riscv_in_isr;

static __always_inline uint32_t _read_csr(const char *reg) {
    if(strcmp(reg, "mepc") == 0) {
        return uapi_csr.uepc;
    } else if(strcmp(reg, "mvendorid") == 0) {
        return uapi_csr.uvendorid;
    } else if(strcmp(reg, "marchid") == 0) {
        return uapi_csr.uarchid;
    } else if(strcmp(reg, "mimpid") == 0) {
        return uapi_csr.uimpid;
    } else if(strcmp(reg, "misa") == 0) {
        return uapi_csr.uisa;
    } else if(strcmp(reg, "mhartid") == 0) {
        return uapi_csr.uhartid;
    } else if(strcmp(reg, "mtval") == 0) {
        return 0x0;
    } else {
        core_panic(PANIC_GENERAL_ERROR, "Unsupported CSR read");
    }
}

static __always_inline void _write_csr(const char *reg, uint32_t val) {
    if(strcmp(reg, "mtvec") == 0) {
        uapi_csr.utvec = val;
    } else if(strcmp(reg, "mie") == 0) {
        uapi_csr.uie = val;
        if(!riscv_in_isr) {
            _ecall1(ECALL_CSRRW_UIE, 0x0);
            _ecall1(ECALL_CSRRW_UIE, uapi_csr.uie);
        }
    } else if(strcmp(reg, "mepc") == 0) {
        uapi_csr.uepc = val;
    } else {
        core_panic(PANIC_GENERAL_ERROR, "Unsupported CSR write");
    }
}

static __always_inline uint32_t _swap_csr(const char *reg, uint32_t val) {
    (void)reg;
    (void)val;
    core_panic(PANIC_GENERAL_ERROR, "Unsupported CSR swap");
}

static __always_inline void _set_csr(const char *reg, uint32_t val) {
    if(strcmp(reg, "mie") == 0) {
        if(riscv_in_isr) {
            uapi_csr.uie |= val;
        } else {
            _ecall1(ECALL_CSRRW_UIE, 0x0);
            uint32_t tmp = uapi_csr.uie | val;
            uapi_csr.uie = tmp;
            _ecall1(ECALL_CSRRW_UIE, tmp);
        }
    } else if(strcmp(reg, "mstatus") == 0) {
        /* ignored */
    } else {
        core_panic(PANIC_GENERAL_ERROR, "Unsupported CSR set");
    }
}

static __always_inline void _clear_csr(const char *reg, uint32_t val) {
    if(strcmp(reg, "mie") == 0) {
        if(riscv_in_isr) {
            uapi_csr.uie &= ~val;
        } else {
            _ecall1(ECALL_CSRRW_UIE, 0x0);
            uint32_t tmp = uapi_csr.uie & (~val);
            uapi_csr.uie = tmp;
            _ecall1(ECALL_CSRRW_UIE, tmp);
        }
    } else {
        core_panic(PANIC_GENERAL_ERROR, "Unsupported CSR clear");
    }
}

#define read_csr(reg) _read_csr(XTSTR(reg))
#define write_csr(reg, val) _write_csr(XTSTR(reg), val)
#define swap_csr(reg, val) _swap_csr(XTSTR(reg), val)
#define set_csr(reg, val) _set_csr(XTSTR(reg), val)
#define clear_csr(reg, val) _clear_csr(XTSTR(reg), val)

