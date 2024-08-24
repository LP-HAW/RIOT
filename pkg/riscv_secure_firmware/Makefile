PKG_NAME = riscv_secure_firmware
PKG_URL = git@github.com:LP-HAW/RV32-SecureFirmware.git
PKG_VERSION = 893572769532d6af4c78a405949abd19910ec905
PKG_LICENSE = unknown

include $(RIOTBASE)/pkg/pkg.mk

.PHONY: riscv_secure_firmware riscv_secure_firmware_stubs

ifneq (,$(filter cryptoservice_stubs,$(USEMODULE)))
  all: riscv_secure_firmware riscv_secure_firmware_stubs
else
  all: riscv_secure_firmware
endif

riscv_secure_firmware:
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR) BINDIR=$(PKG_BUILD_DIR)/bin
	@cp $(PKG_BUILD_DIR)/bin/SecureFirmware.elf $(BINDIR)/$(PKG_NAME).elf

riscv_secure_firmware_stubs: riscv_secure_firmware
	$(QQ)"$(MAKE)" -C $(PKG_BUILD_DIR)/bin/stubs -f $(CURDIR)/Makefile.stubs

clean::
	@rm -rf $(BINDIR)/$(PKG_NAME).elf
