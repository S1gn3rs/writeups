#include <stdio.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>

#include "../shellcode_base.c"

int SCMP_SYS(syscall_name);

typedef void * scmp_filter_ctx;

scmp_filter_ctx ctx;

void addRule(int rule)
{
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, rule, 0))
    {
        _exit(-rule);
    }
}

void dropSyscalls()
{
    int rc = -1;

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) {
        seccomp_reset(ctx, SCMP_ACT_KILL);
        _exit(-1);
    }
    seccomp_arch_add(ctx, SCMP_ARCH_X86);
    addRule(__NR_read);
    addRule(__NR_open);
    addRule(__NR_close);
    addRule(__NR_stat);
    addRule(__NR_fstat);
    addRule(__NR_lstat);
    addRule(__NR_poll);
    addRule(__NR_lseek);
    addRule(__NR_mmap);
    addRule(__NR_mprotect);
    addRule(__NR_munmap);
    addRule(__NR_brk);
    addRule(__NR_execve);
    seccomp_load(ctx);
}

int main(int argc, char ** argv)
{
    void *shellcode;
    shellcode = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    puts("SILENCE, FOUL DAEMON!");
    fflush(stdout);
    dropSyscalls();

    read(0, shellcode, 0x1000);
    ((void(*)())shellcode)();
}