
#ifndef MY_ZHAO_FIFO_H
#define MY_ZHAO_FIFO_H
#define TRUE 1
#define FALSE 0
typedef int int32_t ;

/*������ɾ��*/
/*�����ڴ�Ĵ�����ɾ��*/
extern int32_t CreateShm(char *fname,int id, int32_t I32ShmSize);
extern int32_t DeleteShm(int32_t I32ShmId);

/*�����ڴ�����������*/
extern void * AttachShm(int32_t I32ShmId);
extern int32_t DetachShm(const void * pCShmAddr);
#endif 