#include "shm.h"
/*UI��COMMģ���ͨ�����õĹ����ڴ�ṹ��*/
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
	
    /* ���������ڴ�*/
    if ((I32ShmId = shmget(key, I32ShmSize, IPC_CREAT| 0666)) == -1) 
		{
       	perror("create shm error\n");
    }
    return I32ShmId;
}
void *  AttachShm(int I32ShmId)
{
	void * pAddr;
	/*���ӹ����ڴ�*/
    if ( (pAddr = shmat(I32ShmId,NULL,0)) == (void *)(-1) ) 
    {
        printf("open shm error\n");
    }
    return pAddr;
}
/*���빲���ڴ�*/
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
 * FUNCTION     : ɾ�������ڴ�
 * INPUT        : I32ShmId	: �����ڴ��ID
 * RETURN       : TRUE		: �ɹ�
 *              : FALSE		: ����
 * PROGRAMMED   : yjlee
 * DATE(ORG)    : 20091206
 * REMARKS      : 
 ********************************************************************/
int32_t DeleteShm(int32_t I32ShmId)
{
    /* ɾ�������ڴ� */
    if (shmctl(I32ShmId, IPC_RMID, NULL) == -1) 
	{
       printf("delet error\n");
		return FALSE;
	}
    return TRUE;
}
