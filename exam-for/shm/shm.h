
#ifndef MY_ZHAO_FIFO_H
#define MY_ZHAO_FIFO_H
#define TRUE 1
#define FALSE 0
typedef int int32_t ;

/*创建与删除*/
/*共享内存的创建与删除*/
extern int32_t CreateShm(char *fname,int id, int32_t I32ShmSize);
extern int32_t DeleteShm(int32_t I32ShmId);

/*共享内存的连接与分离*/
extern void * AttachShm(int32_t I32ShmId);
extern int32_t DetachShm(const void * pCShmAddr);
#endif 
