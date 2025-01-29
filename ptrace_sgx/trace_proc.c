#define _GNU_SOURCE 
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include "signal.h"
#include "stdio.h"
#include <sys/mman.h>
#include "string.h"
#include <errno.h>
#include <sys/syscall.h>
#include <sched.h>

#define NEXT_SEG_SIGN 0
#define NEXT_SEG_LOOP  1 
#define NEXT_SEG_ADD  2 
char* states[3] = {"NEXT_SEG_SIGN", "NEXT_SEG_LOOP", "NEXT_SEG_ADD"};

int state = NEXT_SEG_SIGN; // initial state until the program hits the signature function

////////////Debug enclave addresses /////////////////////////
// #define signature_func  0x00007ffff5834000
// #define loop_begin  0x00007ffff5947000
// #define add_func  0x00007ffff599b000
////////////Debug enclave addresses /////////////////////////

////////////Intel enclave addresses /////////////////////////
#define signature_func  0x00007ffff5839000
#define loop_begin  0x00007ffff5961000
#define add_func  0x00007ffff59c4000
#define var_guess 0x00007ffff5ab6000
////////////Intel enclave addresses /////////////////////////

// ////////////Repr enclave addresses /////////////////////////
// #define signature_func  0x00007ffff5839000
// #define loop_begin  0x00007ffff5961000
// #define add_func  0x00007ffff59c4000
// #define var_guess 0x00007ffff5ab6000
// ////////////Repr enclave addresses /////////////////////////



u_int32_t count=0;

void modify_memory_permissions(pid_t tracee, u_int64_t addr, u_int64_t size, int permissions);

void change_state(pid_t tracee, void* faulting_addr){
    u_int64_t addr= (u_int64_t) faulting_addr;
    switch (addr)
    {
    case (signature_func):
        if(state != NEXT_SEG_SIGN){
            printf("ISSUE: got the signature when in state %s\n", states[state]);
        }
        printf("Hit the signature func. Revoking Permissions of loop_begin and resetting permissions of signature func \n");
        printf("NEXT_SEG_SIGN -> NEXT_SEG_LOOP\n");
        printf("Tracee pid: %d\n", tracee);
        
        modify_memory_permissions(tracee, signature_func, 4096, PROT_READ|PROT_EXEC);
        modify_memory_permissions(tracee, loop_begin, 4096, PROT_NONE);
       
        // modify_memory_permissions(tracee, var_guess, 4096, PROT_NONE);


        state = NEXT_SEG_LOOP;
        break;
    case (loop_begin):
        if(state != NEXT_SEG_LOOP){
            printf("ISSUE: got the loop addr when in state %s\n", states[state]);
        }
        printf("Hit the loop_begin. Revoking Permissions of add  and resetting permissions of loop_begin \n");
        printf("NEXT_SEG_LOOP -> NEXT_SEG_ADD\n");
        
        modify_memory_permissions(tracee, loop_begin, 4096, PROT_READ|PROT_EXEC);
        // modify_memory_permissions(tracee, var_guess, 4096, PROT_READ|PROT_WRITE);

        modify_memory_permissions(tracee, add_func, 4096, PROT_NONE);


        state = NEXT_SEG_ADD;
        printf("Count: %d\n", count);
        break;

    case (add_func):
        if(state != NEXT_SEG_ADD){
            printf("ISSUE: got the add  addr when in state %s\n", states[state]);
        }
        printf("Hit the add func. Revoking Permissions of loop_begin  and resetting permissions of add \n");
        printf("WAIT_FOR_SIGN -> IN_LOOP_WAIT_FOR_ADD\n");
        
        modify_memory_permissions(tracee, add_func, 4096, PROT_READ|PROT_EXEC);
        modify_memory_permissions(tracee, loop_begin, 4096, PROT_NONE);
        // modify_memory_permissions(tracee, var_guess, 4096, PROT_NONE);



        state = NEXT_SEG_LOOP;
        count++;
        break;
    
    
    default:
        printf("ISSUE: Unexpected Faulting addr %llx\n", addr);
        // modify_memory_permissions(tracee, var_guess, 4096, PROT_READ|PROT_WRITE);

        break;
    }

}

void wait_for_enter(){
    int c;
    printf("Press enter to continue......\n");
    while ((c= getchar()) != '\n' && c != EOF) {}
    return;

}

void modify_memory_permissions(pid_t tracee, u_int64_t addr, u_int64_t size, int permissions){
    long ret;
    // save the state of the program
    struct user_regs_struct orig_regs;
    struct user_regs_struct mod_regs;
    ret = ptrace(PTRACE_GETREGS,tracee,NULL,&orig_regs);
    if(ret==-1){perror("GETREGS");}
    memcpy(&mod_regs,&orig_regs,sizeof(struct user_regs_struct));
    
    printf("RAX: %llx\n", orig_regs.rax);
    printf("RIP: %llx\n", orig_regs.rip);
    // setup the registers for the system call
    mod_regs.rax = SYS_mprotect;
    mod_regs.rdi=addr;
    mod_regs.rsi=size;
    mod_regs.rdx=permissions;
    ret = ptrace(PTRACE_SETREGS,tracee,NULL,&mod_regs);
    if(ret==-1){perror("SETREGS");}

    // insert the systemcall instruction in place of the current instruction pointed to by rip
    // char orig_inst[2];
    u_int64_t orig_inst;
    errno=0;
    orig_inst = ptrace(PTRACE_PEEKTEXT,tracee, orig_regs.rip,NULL);
    if(orig_inst == -1 && errno){perror("PEEKTEXT");}

    u_int64_t new_inst = 0x000000000000050f;
    ret = ptrace(PTRACE_POKETEXT,tracee,orig_regs.rip,new_inst);
    if(ret==-1){perror("POKETEXT");}
    
    // do the call
    ret = ptrace(PTRACE_SYSCALL, tracee, NULL, NULL);
    if(ret==-1){perror("SYSCALL");}
   
    int status;
    wait(&status); // signaled syscall entry

    ret = ptrace(PTRACE_SYSCALL, tracee, NULL, NULL);
    if(ret==-1){printf("syscall 2 -1\n");}


    wait(&status); // signaled syscall exit
    printf("second wait done\n");
   
    ret = ptrace(PTRACE_GETREGS,tracee,NULL,&mod_regs); // get syscall return value
    if(ret==-1){printf("get call ret val -1\n");}


    printf("Syscall return %llx\n", mod_regs.rax);


    // restore the state of the program
    ret = ptrace(PTRACE_POKETEXT,tracee, orig_regs.rip,orig_inst);
    if(ret==-1){perror("PTRACE_POKETEXT");}

    ret =ptrace(PTRACE_SETREGS,tracee,NULL,&orig_regs);
    if(ret==-1){printf("set regs -1\n");}


    return;
}
int main(void){
    pid_t tracee;
    
    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(2, &mask);
    int r;

    tracee = fork();
    if(!tracee){
        // the tracee
        ptrace(PTRACE_TRACEME,0,NULL,NULL);
        // kill(getpid(),SIGSTOP);
       
        // execlp("/home/samy/playground/test_tracer", NULL,0);
        // execlp("/home/samy/SampleEnclave/app", NULL,0);
        execlp("/home/samy/SGXDataCenterAttestationPrimitives/SampleCode/QuoteGenerationSample/app", NULL,0);


        

        // 0x7ffff6c510c0
    }else{
        r = sched_setaffinity(tracee,sizeof(mask),&mask);
        //tracer
        printf("Tracee pid: %d\n", tracee);
        int status;
        wait(&status);
        printf("Tracee stopped\n");
        ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_TRACESYSGOOD);
        ptrace(PTRACE_CONT,tracee, NULL,0);

        while(1){
            wait(&status);
            printf("hello\n");
            if(WIFEXITED(status)){
                printf("Tracee exited\n");
                // printf("")
                printf("Count: %d\n", count);

                return 0;
            }

            if(WIFSTOPPED(status)){
                printf("Tracee got a signal\n");
                int signal = WSTOPSIG(status);

                if(signal == SIGSEGV){
                    printf("Its a SIGSEGV\n");
                    struct user_regs_struct regs;
                    ptrace(PTRACE_GETREGS, tracee, NULL, &regs);
                    
                    // get sig info
                    siginfo_t segfault;  
                    ptrace(PTRACE_GETSIGINFO, tracee, NULL, &segfault);

                    void* fault_addr = segfault.si_addr;
                    printf("Segmentation fault at address: %p\n", fault_addr);
        
       
                    switch (segfault.si_code) {
                        case SEGV_MAPERR: // Address not mapped
                            printf("Address not mapped\n");
                            break;
                        case SEGV_ACCERR: // Invalid permissions
                            printf("Invalid permissions for address\n");
                            break;
                    }

                   
                    printf("Program counter: %llx\n", regs.rip);

                    // modify_memory_permissions(tracee, 0x555555559000, 4096, PROT_READ|PROT_WRITE);
                    // modify_memory_permissions(tracee, 0x7ffff6c51000, 4096, PROT_READ|PROT_WRITE);
                    
                    // modify_memory_permissions(tracee, 0x00007ffff5946000, 4096, PROT_READ|PROT_EXEC);
                    change_state(tracee,fault_addr);
                    wait_for_enter();

                    // return 0;
                }

                if(signal == SIGTRAP){
                    printf("SIGTRAP\n");
                    wait_for_enter();

                    // modify_memory_permissions(tracee, 0x555555559000, 4096, PROT_NONE);
                    // modify_memory_permissions(tracee, 0x7ffff6c51000, 4096, PROT_NONE);

                    modify_memory_permissions(tracee, signature_func, 4096, PROT_NONE);

                    


                    // wait_for_enter();


                }

                if(signal == SIGSTOP){
                    printf("SIGSTOP\n");
                    // wait_for_enter();
                    // modify memory permissions
                    // modify_memory_permissions(tracee, 0x555555559000, 4096, PROT_NONE);
                }
                // return 0;
                ptrace(PTRACE_CONT,tracee, NULL,0);
            }

           
            
        }
    }
}

// Add address -->> 0x7ffff599b380
// loop address --> 0x00007ffff5947060