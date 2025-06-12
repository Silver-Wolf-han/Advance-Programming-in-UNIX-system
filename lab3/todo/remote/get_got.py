from pwn import *
elf = ELF('./gotoku')
print("main =", hex(elf.symbols['main']))
print("{:<12s} {:<10s} {:<10s}".format("Func", "GOT Offset", "Symbol Offset"))
with open("got.txt", "w") as fd:
    for s in [ f"gop_{i+1}" for i in range(1200)]:
        if s in elf.got:
            print("{:<12s} {:<10x} {:<10x}".format(s, elf.got[s], elf.symbols[s]))
            fd.write("0x{:x}\n".format(elf.got[s]))
