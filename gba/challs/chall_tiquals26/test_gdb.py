import subprocess
import time

def run():
    # start mgba
    p_mgba = subprocess.Popen(["mgba", "-g", "vm.gba"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    # run gdb
    gdb_cmds = """
target remote :2345
set architecture arm

# 0x02000000 (IN_REGS_ADDR) = [1,2,3,4,5,6,7,8]
set {unsigned long long} 0x02000000 = 1
set {unsigned long long} 0x02000008 = 2
set {unsigned long long} 0x02000010 = 3
set {unsigned long long} 0x02000018 = 4
set {unsigned long long} 0x02000020 = 5
set {unsigned long long} 0x02000028 = 6
set {unsigned long long} 0x02000030 = 7
set {unsigned long long} 0x02000038 = 8

# 0x02000140 (IN_BC_LEN_ADDR) = 2
set {int} 0x02000140 = 2

# 0x02000144 (IN_BC_ADDR) = "\x00\x00"
set {unsigned char} 0x02000144 = 0x00
set {unsigned char} 0x02000145 = 0x00

# 0x02001148 (OUT_DONE_ADDR) = 0
set {int} 0x02001148 = 0

watch *0x02001148
continue

printf "DONE: 0x%08x\n", *(int*)0x02001148
printf "STATUS: %d\n", *(int*)0x02001140
printf "STEPS: %d\n", *(int*)0x02001144
printf "REGS[0]: %llu\n", *(unsigned long long*)0x02001000
printf "REGS[1]: %llu\n", *(unsigned long long*)0x02001008
printf "REGS[2]: %llu\n", *(unsigned long long*)0x02001010
printf "REGS[3]: %llu\n", *(unsigned long long*)0x02001018
printf "REGS[4]: %llu\n", *(unsigned long long*)0x02001020
printf "REGS[5]: %llu\n", *(unsigned long long*)0x02001028
printf "REGS[6]: %llu\n", *(unsigned long long*)0x02001030
printf "REGS[7]: %llu\n", *(unsigned long long*)0x02001038

quit
"""
    with open("cmds.gdb", "w") as f:
        f.write(gdb_cmds)
        
    subprocess.run(["gdb", "-q", "-x", "cmds.gdb"], timeout=10)
    p_mgba.kill()

if __name__ == "__main__":
    run()
