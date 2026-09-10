# FILE structures 

Useful references: 
- https://chovid99.github.io/posts/file-structure-attack-part-1/
- https://gsec.hitb.org/materials/sg2018/WHITEPAPERS/FILE%2520Structures%2520-%2520Another%2520Binary%2520Exploitation%2520Technique%2520-%2520An-Jie%2520Yang.pdf
- https://faraz.faith/2020-10-13-FSOP-lazynote/ (cute writeup with libc code explained) 

An open stream is handled with a **FILE object**, which is an ``_IO_FILE_plus`` structure:

```c 
struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};
```

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

Check its structure and offsets in gdb with `ptype /o struct _IO_FILE` , and in pwndbg with `dq &_IO_2_1_stdout_`

All the opened streams are joined in a linked list by the _chain field, which allows GLIBC to easily close them all on exit.
Remember that all ``_IO_FILE_plus``  structs have got a vtable field!!! (important)

The ``_wide_data`` field **points to a similar structure** which is the buffer for `wide oriented streams` (can be exploited in FSOP variants which use `_IO_wfile_jumps` hijacking) 
(see House of Apple 1 and 2 here: https://corgi.rip/posts/leakless_heap_1/)

## About buffering
To avoid many small writes, output is flushed only when certain conditions occur:
- file/pipe: fully buffered -> flush when the buffer is full
- stdout:
  - if connected to a terminal: line buffered -> flush on '\n' or when the buffer is full
  - if redirected to a file/pipe: fully buffered -> flush only when the buffer is full
- stderr: unbuffered -> every write goes out immediately, often there's `_IO_buf_base == _IO_buf_end` (often both NULL = no buffer)


## Build fake structs

The way to do fsop is: 
### Overwriting existing file structures
 
If you have an **arb write** (tcache poisoning, write-what-where, format string), you can write relevant fields into an already existing structure in libc 

example: `_IO_2_1_stdout_` , `_IO_2_1_stdin_` -> usually to leak/write things, but i need to know the libc address

### Building fake file structures 

Write a fake struct from scratch if you have:
- a LOT of space
- you know the address of that memory 

usually: heap chunks, .bss, stack (sometimes)

Our friend pwntools helps us with the FileStructure object that doesn't make you calculate offsets by hand :) docs here: https://docs.pwntools.com/en/stable/filepointer.html

Famous targets:
- `_IO_list_all` (used in House of Orange): overwrite this with your heap chunk address so that `exit`/ `ret` after main -> `_IO_flush_all_lockp` -> fake struct is at the head of the list and the fake vtable will be executed. I need to know the libc + heap addresses
- `FILE*`: if the program saves the `fopen` result in a global variable (`.bss`), overwrite it to make it point to the heap chunk -> I need to know the libc addr + binary base

## Exploit using vtable corruption 

Source: https://niftic.ca/posts/fsop/ 

The vtable field of ``_IO_FILE_plus`` structure points to a set of function pointers. 
These functions are GLIBC internal functions called by higher level functions like puts, fgets or printf.
In the case of standard streams like stdout, the vtable points to the table ``_IO_file_jumps``.

### Example 

`printf` -> `_IO_file_xsputn` -> `vtable address`

if we control where the vtable points to -> we control which function gets called internally inside a printf.
 
#### Tip:
When a vtable function is called, the first argument (`rdi`) is the pointer to the FILE struct (the fake ``_IO_FILE_plus``), vtable is at `rdi + 0xd8`.
If you can make the vtable point to a gadget like `setcontext+61` or `getkeyserv_handle`, that gadget will interpret the FILE struct as an `ucontext` struct, loading registers and the stack pointer from offsets you control. 
-> you can place regs value and the new rsp inside the fake struct -> pivoting to a rop chain

- info about setcontext: https://man7.org/linux/man-pages/man3/setcontext.3.html
- info about ucontext struct: https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/unix/sysv/linux/x86/sys/ucontext.h#L142

Before dereferencing the vtable, GLIBC checks if the address is inside the ``__libc_IO_vtables`` section -> **we can’t redirect the vtable to anywhere we want**.
`IO_vtable_check` checks:
- if `IO_accept_foreign_vtables` holds `&_IO_vtable_check` (a magic compatibility value, set when the lib sets the standard vtables) -> skips check and foreign vtables are accepted.
- default: check is enforced




From libc 2.42:

``` c
void (*IO_accept_foreign_vtables) (void) attribute_hidden;   // default: NULL (it's in BSS)

void attribute_hidden
_IO_vtable_check (void)
{
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
  PTR_DEMANGLE (flag);
  if (flag == &_IO_vtable_check) // IO_accept_foreign_vtables == &_IO_vtable_check
    return;
  // ...
  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```

```c 
if (_IO_2_1_stdin_.vtable != &_IO_file_jumps || ...)
  IO_set_accept_foreign_vtables (&_IO_vtable_check); // disables check

```


#### Bypass:

Until libc 2.31 you can just overwrite the `IO_accept_foreign_vtables` variable with the correct address: 
- leak `IO_accept_foreign_vtables` address, `IO_vtable_check` address from libc 
- using an arbitrary write, overwrite `IO_accept_foreign_vtables = &_IO_vtable_check`

From 2.32 onwards there's pointer mangling so it's not funny anymore, needs a lot of effort.

Better way now:
- inside the ``__libc_IO_vtables section`` there are other jump tables for other types of streams (``_IO_str_jumps`` table, ``_IO_wfile_jumps`` table)
- tables contain function pointers: I can modify the vtable pointer to internally call any of these functions (instead of ``_IO_file_xsputn``, for example) while still passing the `IO_validate_vtable` check
- some of the functions in these tables have specific code paths which can lead to arbitrary code execution



### angry-FSROP

You can find every exploitable path using angr, details here https://blog.kylebot.net/2022/10/22/angry-FSROP/ (it's a pain, not funny)


## Exploit without corrupting vtables


### Read and write arbitrary memory using stdout  

`_IO_file_overflow / _IO_new_file_overflow`: called everytime `stdio` must empty its write buffer.

how to reach it:
- `printf` -> _IO_file_xsputn -> buffer full or incoherent state -> overflow 
- `exit` -> `_IO_flush_all_lockp` -> for every file with pending queue it does `_IO_OVERFLOW(fp, EOF)` -> `ch == EOF` -> `_IO_do_flush`

#### How to leak

##### Changing flags:

 when libc writes on a file struct, it calls `_IO_new_file_overflow` (handles file structures):

```c
if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)   // am i not writing already?
  {
    if (f->_IO_buf_base == 0)        // no buf -> alloc a new one
        // ...

    f->_IO_write_base = f->_IO_write_ptr = f->_IO_buf_base; 
    f->_IO_read_ptr = f->_IO_read_end = f->_IO_read_base;   
    // ...
    f->_flags |= _IO_CURRENTLY_PUTTING;
  }
```

If `_IO_CURRENTLY_PUTTING` is = 0 -> reinitializes write_base e write_ptr correctly, so if i want to hijack them i must set the flag = 1 on my fake structure

- `0xFBAD0000` = fake struct is valid 
- `0xFBAD1800` = valid but with flag `_IO_CURRENTLY_PUTTING (0x0800)` = 1, `_IO_IS_APPENDING = 0x1000`

`_IO_IS_APPENDING` says that the file is opened in append mode or that the stream is in a state where writes must happen from the end of the file.
If set, libc moves the file offset at its end -> new data will be added after the stream without overwriting the existing content.


To leak by corrupting stdout:
```
+0x00  flags        = 0xFBAD1800
+0x08  _IO_read_ptr  = 0
+0x10  _IO_read_end  = 0
+0x18  _IO_read_base = 0
+0x20  _IO_write_base = addr        ← buf to print start
+0x28  _IO_write_ptr  = addr+size   ← end
+0x30  _IO_write_end  = addr+size
+0x38  _IO_buf_base   = 0
```

I'm not touching ``_IO_buf_end (0x40)``, ``_IO_save_*``, ``_chain (0x68)``, ``_fileno (0x70)``, ``_lock (0x88)`` and the vtable (0xD8).

At the next `printf`,  libc calls `_IO_file_xsputn`: 
- `_IO_file_xsputn` sees `_IO_write_ptr = _IO_write_end` and calls `_IO_new_file_overflow`
- `_IO_new_file_overflow` checks `_IO_write_ptr > _IO_write_base`, with our corruption it will be `write_ptr - write_base = size` 
- `_IO_do_write(f, write_base, write_ptr - write_base)` is called!

after this, libc resets the pointers (`write_ptr = write_base`) and proceeds normally.

Tip: if ``_IO_read_end != _IO_write_base`` ->  ``_IO_do_write`` tries to do `lseek`. On stdout (fd = 1) it fails, but on a real file it corrupts the output. Fix: set `_IO_read_end = _IO_write_base`

###### About stderr

Corrupting `stderr` is not a good idea because it leads to `_exit` -> `_IO_flush_all_lockp` ( where the `main` frame has already been destroyed with `leave; ret` -> there is no main stack anymore :( ) and the only thing i can do is corrupting the vtable to go to system or one gadget, or (if possible) use `setcontext+61` to pivot to a rop chain written to another controlled memory area before triggering the exit.



#### Arbitrary write 

Set:
- ``_IO_buf_base`` = target, 
- `_IO_buf_end = target+size`, 
- `write_base = write_ptr = target`, 
- flags with `_IO_CURRENTLY_PUTTING = 1`, 
- `_IO_write_ptr < _IO_write_end`

The next printf output is copied (with memcpy) into target instead of the real buffer. 

##### Example

Build a fake struct over `_IO_2_1_stdout_`:

+0x00  flags         = 0xFBAD1800
+0x20  _IO_write_base = target
+0x28  _IO_write_ptr  = target
+0x30  _IO_write_end  = target + 0x1000
+0x38  _IO_buf_base   = target
+0x40  _IO_buf_end    = target + 0x1000

Next printf writes the payload bytes at `target`.

You can do the same thing with `stdin` (by overwriting ``_IO_buf_base``, ``_IO_buf_end``): at the next `scanf`/`fread` the user input will be written where i want instead of writing it into the original buffer.


## Advanced and very cursed things 

### House of Peach
The vtable used for `sprintf`/ `sscanf` (``_IO_str_jumps``) has methods like `_IO_str_overflow` and `_IO_str_finish` which internally call `malloc` and `free`.
You can use a fake file struct to make libc do arbitrary alloc or free bypassing heap constraints :)
TODO

### House of Emma / Kiwi
Abuse _IO_cookie_jumps, _IO_obstack_jumps
TODO


