#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <ucontext.h>
#include <signal.h>

//#define DEBUG 1

struct jump_entry {
    uint64_t rip;
    uint64_t mask;
    uint64_t value;
    uint64_t target;
};

extern struct jump_entry JUMP_TABLE[];

void fixer(int signum, siginfo_t *info, void *_ctx){
    ucontext_t *ctx = _ctx;
    mcontext_t *regs = &ctx->uc_mcontext;
    struct jump_entry *entry = JUMP_TABLE;
    uint64_t *rip = (uint64_t *)&regs->gregs[REG_RIP];
    uint64_t efl = regs->gregs[REG_EFL];
#ifdef DEBUG
    printf("RIP: 0x%llx EFL: 0x%llx\n", *rip, efl);
#endif

    while(entry->rip){
#ifdef DEBUG
        printf("entry->rip = 0x%llx, entry->mask = 0x%04llx, entry->value = 0x%04llx, entry->target = 0x%llx\n",
            entry->rip, entry->mask, entry->value, entry->target);
#endif
        if(*rip == entry->rip){
            if((efl & entry->mask) == entry->value){
                *rip = entry->target;
                return;
            }
        }
        entry++;
    }
}

void __attribute__((constructor)) setup(){
    struct sigaction action = {
        .sa_sigaction = fixer,
        .sa_flags = SA_SIGINFO
    };
    sigaction(SIGTRAP, &action, NULL);
}
