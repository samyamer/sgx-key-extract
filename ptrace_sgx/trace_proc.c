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
    
    printf("RAX: %lx\n", orig_regs.rax);
    printf("RIP: %lx\n", orig_regs.rip);
    // setup the registers for the system call
    mod_regs.rax = 10;
    mod_regs.rdi=addr;
    mod_regs.rsi=size;
    mod_regs.rdx=permissions;
    ret = ptrace(PTRACE_SETREGS,tracee,NULL,&mod_regs);
    if(ret==-1){perror("SETREGS");}

    // insert the systemcall instruction in place of the current instruction pointed to by rip
    // char orig_inst[2];
    long orig_inst;
    errno=0;
    orig_inst = ptrace(PTRACE_PEEKTEXT,tracee, orig_regs.rip,NULL);
    if(orig_inst == -1 && errno){perror("PEEKTEXT");}

    char syscall_inst[2]={0x0f,0x05};
    ret = ptrace(PTRACE_POKETEXT,tracee,orig_regs.rip,0x0f05UL);
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
    if(WIFEXITED(status)){
        printf("Tracee exited when it ll\n");
    }

    if(WIFSTOPPED(status)){
        printf("stopeed in syscall\n");
        int signal = WSTOPSIG(status);
        if(signal == SIGTRAP){
            printf("SIGTRAP\n");
        }

        if(signal == SIGSTOP){
            printf("sigstop\n");
         }


        
    }
    ret = ptrace(PTRACE_GETREGS,tracee,NULL,&mod_regs); // get syscall return value
    if(ret==-1){printf("get call ret val -1\n");}


    printf("Syscall return %lx\n", mod_regs.rax);

    // restore the state of the program
    ret = ptrace(PTRACE_POKETEXT,tracee,orig_regs.rip,orig_inst);
    if(ret==-1){printf("restore text -1\n");}

    ret =ptrace(PTRACE_SETREGS,tracee,NULL,&orig_regs);
    if(ret==-1){printf("set regs -1\n");}


    return;
}
int main(void){
    pid_t tracee;

    tracee = fork();
    if(!tracee){
        // the tracee
        ptrace(PTRACE_TRACEME,0,NULL,NULL);
        // kill(getpid(),SIGSTOP);
        execlp("/home/samy/playground/test_tracer", NULL,0);
    }else{
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
                return 0;
            }

            if(WIFSTOPPED(status)){
                printf("Tracee got a signal\n");
                int signal = WSTOPSIG(status);

                if(signal == SIGSEGV){
                    printf("Its a SIGSEGV\n");
                    struct user_regs_struct regs;
                    ptrace(PTRACE_GETREGS, tracee, NULL, &regs);
                    
                   
                    printf("Program counter: %llx\n", regs.rip);
                    return 0;
                }

                if(signal == SIGTRAP){
                    printf("SIGTRAP\n");
                    modify_memory_permissions(tracee, 0x555555559000, 4096, PROT_NONE);

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