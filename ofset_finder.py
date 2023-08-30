#!/usr/bin/env python

from __future__ import print_function
from pwn import *
import os
import subprocess
import sys  # Import the sys module

# Check if the correct number of arguments is provided
if len(sys.argv) != 2:
    log.warn("Usage: python script_name.py path_to_binary")
    sys.exit(1)

binary_path = sys.argv[1]  # Get the path to the binary from command-line arguments

# Load the ELF binary
elf = ELF(binary_path)

# Start the process using a context manager
with process(binary_path) as p:
    # Send cyclic input to trigger potential buffer overflow
    try:
        p.sendline(cyclic(1000, n=8))
        p.wait()
        # Analyze the core dump to find the offset
        core = p.corefile
        offset = cyclic_find(core.read(core.rsp, 8), n=8)
    except:
        p.close()
        p = process([binary_path,cyclic(1000, n=8)])
        p.wait()
        # Analyze the core dump to find the offset
        core = p.corefile
        offset = cyclic_find(core.read(core.rsp, 8), n=8)


# Print the offset
log.success("Offset: {}".format(offset))
#clear core files
os.system('rm -rf ./core.*')
