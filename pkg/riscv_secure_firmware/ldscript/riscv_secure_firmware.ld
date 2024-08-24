INCLUDE fe310.ld

/* RIOT definitions */
_rom_start_addr = __flash_normal_start;
_ram_start_addr = __ram_normal_start;
_rom_length = __flash_normal_size;
_ram_length = __ram_normal_size;

INCLUDE riscv.ld
