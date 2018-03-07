# Smashing the Stack

## Part 1 - Control Flow

To change control flow in the **if** statement (line 11), we should overflow the buffer variable **buff** such that the variable before it (with bigger address value) **a** will be overwritten.

Using GDB, we can see that the distance from the address of the **buff** to the address of the **a** is 268 bytes (256 + 12 bytes of alignment padding).

Thus in order to overwrite **a**, we need 268 bytes of rubbish data, plus exactly 2 bytes of data that represents 0xfeed.

(Why 2 bytes? Think of little endian :P)

Hence we can come up with the following payload construction:

```bash
perl -e 'print "A"x268, "\xed\xfe"'
```

## Part 2 - Find Return Address

We know from part 1 that the memory distance between our victim **buff** to the very first local variable **a** of function `foo` is 268 bytes.

That is telling us, the distance from victim **buff** to the **RET** (return address) of `foo` is 268 + 4 (a) + 8 (SFP) bytes.

From the output of objdump, we get to know that the address of function `bar` is at 0x000000000040057d.

Thus we could form our payload as such:

```bash
perl -e 'print "A"x280, "\x7d\x5\x40"'
```