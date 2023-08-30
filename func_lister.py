from pwn import *
import sys

def print_functions(binary_path):
    elf = ELF(binary_path)

    log.info("List of functions in the binary:")
    for idx, (function_name, function_address) in enumerate(elf.symbols.items(), start=1):
        print(f"\t{idx}. {hex(function_address)}: {function_name:30}")

def main():
    if len(sys.argv) != 2:
        log.warn("Usage: python script_name.py path_to_binary")
        sys.exit(1)

    binary_path = sys.argv[1]
    print_functions(binary_path)

if __name__ == "__main__":
    main()
