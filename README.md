# pearls ret2get + ret2libc
> https://blog.csdn.net/2502_91269216/article/details/148261096  
(get target libc.so.6 from container built by Dockerfile)  

As the blog of 'ret2gets' said, the register 'RDI' and 'RCX' will be set to specific addresses in libc after calling function 'gets' with libc's version >= 2.30. RDI will be ptr of '_IO_stdfile_0_lock' and RCX will be the ptr of '_IO_2_1_stdin_'.  
We can just overwrite the space of return addr(0x88+start_addr), and it needs 3 gets calling.  
1: ensure rsp is assigned with 16bytes before calling printf   
2: gets---> set rdi and rcx register value, and lock it;  
3: fill '_IO_stdfile_0_lock' 's content, the structure of it is just like:  
```c
typedef struct {
    int lock;
    int cnt;
    void *owner;
} _IO_lock_t;
```
Payload will be `b'%p%p$%p#' + p64(0)`, note that the first '$' will subtract 1 after calling `gets`. This filling will be the arguments of following `printf`.  
When calling printf, its first argument is 'RDI'='_IO_stdfile_0_lock'='%p%p#%p#', the second one is 'RSI' (we don't care it), and the third one is 'RCX' which is '_IO_2_1_stdin_'. Thanks to this format, we could get the address of '_IO_2_1_stdin_' and could calculate the libc_base_addr esaily.  
Finally, find a rop gadget ('pop rdi ; ret'), use ret2libc to get shell.  
 
