## mitigations 
- smap 
- kaslr 
- kpti

### canary 
userland canary != kernel space canary 
every thread has a different kernel canary which is != its userland canary



## krop

```asm
pop rdi; ret
init_creds
commit_creds

swapgd_restore_regs_and_return_to_usermode + offset

rdi 
??? 

rip
cs 
eflags
rsp
ss
```

commit_creds wants a cred_structs
i pass it a privileged one, how?
- call a function which generates a struct with root permimssion (requires particular gadgets and it's a pain)

-> easier and more common way: give it init_creds (a symbol in the kernel img) where there is a root struct (sometimes doesn't work but in real word scenarios)

then i need to return to userland to pop a shell, how is it done?
- swap gs: 
    - takes 2 qwords: rdi (useless), gap (useless)
    - then wants an iret frame: `rip (= win function, example: system(/bin/sh) -> mind the stack alignment!), cs = 0x33 (userland code), eflags, rsp, ss`
    - for simple exploits: `eflag` is fixed = `0x202` (`0x200` activates interrupts, `0x2` reserved bit that must be set to 1)

- change page tables if kpti is on 
- edit privileges 
- pop context from the stack (what `iretq` does)

ugly to do by hand, there is a nice function to return to userland: `swapgd_restore_regs_and_return_to_usermode`
I want to jump in it but not at the start but at the offset `+103` to avoid useless pops and checks.
what does it do?
- pops registers
- stack edit: moves gs values to rsp, example: stack that must be used for context switching
why? if kpti is active you can't use a userland stack and a kernel one (it will not be mapped anymore when you return)
-> need a kernel stack but also mapped userland = in cpu_entry area

- push iret frame from the old stack to the context switching one 
- swap page table: `mov rdi, cr3; or rdi, 0x1000; mov cr3, rdi;` -> a simple way to implement kpti is to use 2 page table at adjacent physical pages (new = old + 0x1000)
- then re jump to swap gs and msr value are changed
- iretq -> goes to userland @ win function


# data only attacks

## dirty creds 

task_struct = task assigned to every process (al mio esame di calcolatori (lol) = descrittore di processo, des_proc))
- stored in a double linked list starting from `init_task`
- dynamically allocated on the heap

interesting field: 
- `cred` struct, i want to set `uid = 0` (root)
- usually we set every id to 0
- do not touch `ref_count` otherwise -> crash

### how to exploit 
i need:
- kaslr leak 
- arb read -> walk tasks until exploit
- arb write -> change creds

i want to find the task_struct addr and write to it 
- start from init_task = aslr base + offset
- walk to the next structs
- check if pid == exploit 
- when you find it, use arb read to read the cred struct + arb write to set id = 0

note:
- dirty {something} = corrupt {something} 
- creds vs ring: ring are processor-specific (hardware privileges), creds are os specific (software privileges)


## modprobe
- binary which helps finding the right interpreter to execute a program, example: recognises magic bytes and understands how to execute 

### how to exploit 
- create a binary with magic bytes -> its execution triggers modprobe -> OLD, patched :(
- NOW: socket(0,2,0), info: https://leo1.cc/posts/docs/socket020---reviving-modprobe_path-again/

-> a kernel variable (`modprobe_path`) stores which binary is modprobe
- arb write to overwrite `modprobe_path` with a user controlled file
- trigger `modprobe`


## core_dump
`core_dump` is triggered when a process crashes (`segfault: core_dump`), you can use it to execute an arb command with root privileges (and some other advanced things like container escape)

### mitigations
core_dump and modprobe can be mitigated by `CONFIG_STATIC_USERMODEHELPER` -> if enabled they'll both use read only strings.


## hooks 
- most used: `n_tty_ops` vtable, especially the `ioctl` entry, `ioctl(0,x,y)` gives you rip hijacking with some regs set to x and y
    - then do stack pivoting
- other useful ones in the network stack 


## shellcode 


### dirtypt
write on a page table? map a virtual address to a physical one at ring0

- map any page (even kernel code!) with whatever permission 
- change kernel code and get shellcode 

### rop + shellcode
if we have rop instead on priv esc + context_switching, do 

```asm 
pop rdi -> controlled data  
pop rsi -> number of pages to modify
call set_memory_x(0xcontrolled, n) -> shellcode
```

similar to userland's rop with mprotect + shellcode!

1:37


