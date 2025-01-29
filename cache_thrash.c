#include <sys/mman.h>
#include "errno.h"
#include <stdio.h>
#include "stdlib.h"
#define L2_SIZE 1280*1024
#define L3_SIZE 36*1024*1024

int main(void){
    // Allocate memory double the l2 size
    char* mem = mmap(0, 2*L3_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, 0,0);
    if(mem == MAP_FAILED){
       perror("mmap");
       exit(-1);
    }

    // traverse it 
    while(1){
        for(int i=0; i<2*L3_SIZE; i++){
            mem[i] = 0xff;
        }
    }
}