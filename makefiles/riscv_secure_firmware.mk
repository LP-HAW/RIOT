ifneq (,$(filter riscv_umode,$(USEMODULE)))

SECURE_FIRMWARE_ELF = $(BINDIR)/riscv_secure_firmware.elf

.PHONY: flash-bootloader
flash-bootloader: FLASHFILE := $(shell mktemp --suffix=".elf")
flash-bootloader: all $(SECURE_FIRMWARE_ELF)
	$(Q)cp $(SECURE_FIRMWARE_ELF) $(FLASHFILE)
	$(Q)$(RIOTTOOLS)/riscv_secure_firmware/flash_keys.py $(FLASHFILE) $(KEYFILE)
	$(flash-recipe)
	$(Q)rm $(FLASHFILE)

.PHONY: flash-riot
flash-riot: all $(ELFFILE)
	$(flash-recipe)

endif
