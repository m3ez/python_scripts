#!/usr/bin/env python

from __future__ import print_function
from pwn import *
import os
import sys

def find_offset(binary_path):
    elf = ELF(binary_path)

    with process(binary_path) as p:
        try:
            log.info('Sending cyclic input to trigger potential buffer overflow...')
            p.sendline(cyclic(1000, n=8))
            p.wait()
            core = p.corefile
            # Determine the stack pointer register based on the architecture
            stack_ptr_register = 'rsp' if elf.bits == 64 else 'esp'
            offset = cyclic_find(core.read(getattr(core, stack_ptr_register), 8), n=8)
        except:
            p.close()
            p = process([binary_path,cyclic(1000, n=8)])
            p.wait()
            # Analyze the core dump to find the offset
            core = p.corefile
            offset = cyclic_find(core.read(core.rsp, 8), n=8)

    return offset


def main():
    if len(sys.argv) != 2:
        log.warn("Usage: python script_name.py path_to_binary")
        sys.exit(1)

    binary_path = sys.argv[1]
    
    offset = find_offset(binary_path)

    if offset is not None:
        log.success("Offset: {}".format(offset))
    else:
        log.error("Offset detection failed.")

    # Clean up core files
    os.system('rm -rf ./core.*')

if __name__ == "__main__":
    main()
