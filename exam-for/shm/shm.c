#include "shm.h"
/*UI与COMM模块的通信所用的共享内存结构体*/
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/sem.h>
#include <unistd.h>
#include"stdio.h"


int32_t CreateShm(char *fname,int id, int32_t I32ShmSize)
{
		key_t key; 
		int32_t I32ShmId;	
		key = ftok(fname ,id);
	
    /* 创建共享内存*/
    if ((I32ShmId = shmget(key, I32ShmSize, IPC_CREAT| 0666)) == -1) 
		{
       	perror("create shm error\n");
    }
    return I32ShmId;
}
void *  AttachShm(int I32ShmId)
{
	void * pAddr;
	/*连接共享内存*/
    if ( (pAddr = shmat(I32ShmId,NULL,0)) == (void *)(-1) ) 
    {
        printf("open shm error\n");
    }
    return pAddr;
}
/*分离共享内存*/
int32_t DetachShm(const void * pCShmAddr)
{
    if (shmdt(pCShmAddr) == -1) 
    {
       printf("detach shm error\n");
        return FALSE;
    }
    return TRUE;
}
/*********************************************************************
 * NAME         : DeleteShm
 * FUNCTION     : 删除共享内存
 * INPUT        : I32ShmId	: 共享内存的ID
 * RETURN       : TRUE		: 成功
 *              : FALSE		: 出错
 * PROGRAMMED   : yjlee
 * DATE(ORG)    : 20091206
 * REMARKS      : 
 ********************************************************************/
int32_t DeleteShm(int32_t I32ShmId)
{
    /* 删除共享内存 */
    if (shmctl(I32ShmId, IPC_RMID, NULL) == -1) 
	{
       printf("delet error\n");
		return FALSE;
	}
    return TRUE;
}
