#ifndef AVL_H__
#define AVL_H__
/*
 *������һЩ���õĹ��ܣ����ڴ����
 */
#include <stdio.h>
#include <stdlib.h>

/*�����ڴ�*/
inline void *xalloc(int size)
{
    void *p;
    p = (void *)malloc(size);
    /*����ʧ��*/
    if(p == NULL)
    {
        printf("alloc error\n");
        exit(1);
    }
    return p;
}
/*�ڴ��ͷ�*/
#define xfree(p) free(p)
/*
 *avl�����ݽṹ����ز���
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct AVLTree
{
    unsigned int nData;    /*�洢����*/
    struct AVLTree* pLeft;    /*ָ��������*/
    struct AVLTree* pRight;    /*ָ��������*/
    int nHeight;    /*����ƽ���*/
}AVLTree;

/*�������*/
struct AVLTree* insert_tree(unsigned int nData, struct AVLTree* pNode);

/*���Ҳ������ҵ�����1�����򣬷���0*/
int find_tree(unsigned int data, struct AVLTree* pRoot);

/*ɾ������,ɾ�����нڵ�*/
void delete_tree(struct AVLTree** ppRoot);

/*��ӡ����*/
void print_tree(struct AVLTree* pRoot);
#endif