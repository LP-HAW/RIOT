#!/usr/bin/env python3

import sys
import os
import base64

from elftools.elf.elffile import ELFFile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import PublicFormat, PrivateFormat, Encoding
from cryptography.hazmat.primitives.asymmetric import ec

KEYSTORE_SECTION = 'secrets'
KEYSTORE_SYMBOL = 'KEYS'

def get_keys_offset(elf, section, symbol):
    secrets = elf.get_section_by_name(section)
    assert secrets is not None

    secrets_addr = secrets['sh_addr']
    secrets_offset = secrets['sh_offset']

    symtab = elf.get_section_by_name('.symtab')
    assert symtab is not None

    syms = symtab.get_symbol_by_name(symbol)
    assert syms is not None
    assert len(syms) == 1

    sym_value = syms[0]['st_value']

    return (sym_value - secrets_addr) + secrets_offset

def load_key(filename):

    private_key = None

    if filename is not None:
        with open(filename, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

    if private_key is None:
        private_key = ec.generate_private_key(ec.SECP256R1())

    private_bytes = private_key.private_numbers().private_value.to_bytes(length=32)
    public_bytes = private_key.public_key().public_bytes(
        format=PublicFormat.UncompressedPoint, encoding=Encoding.X962)

    return (private_bytes, public_bytes)


if __name__ == "__main__":
    if(len(sys.argv) < 2):
        print(f'usage: {sys.argv[0]} <elffile> [keyfile]')
        sys.exit(-1)

    root_offset = None
    with open(sys.argv[1], 'rb') as f:
        elf = ELFFile(f)
        root_offset = get_keys_offset(elf, 'secrets', 'CYS_ROOT_KEY')

    platform_offset = None
    with open(sys.argv[1], 'rb') as f:
        elf = ELFFile(f)
        platform_offset = get_keys_offset(elf, 'secrets', 'CYS_PLATFORM_KEY')

    keyfile = sys.argv[2] if len(sys.argv) > 2 else None
    private_key, public_key = load_key(keyfile)
    root_key = os.urandom(16)

    with open(sys.argv[1], 'r+b') as f:
        f.seek(root_offset)
        f.write(root_key)
        f.seek(platform_offset)
        f.write(private_key)
