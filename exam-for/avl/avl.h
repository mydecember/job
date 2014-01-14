#ifndef AVL_H__
#define AVL_H__
/*
 *整理了一些常用的功能，如内存管理
 */
#include <stdio.h>
#include <stdlib.h>

/*申请内存*/
inline void *xalloc(int size)
{
    void *p;
    p = (void *)malloc(size);
    /*申请失败*/
    if(p == NULL)
    {
        printf("alloc error\n");
        exit(1);
    }
    return p;
}
/*内存释放*/
#define xfree(p) free(p)
/*
 *avl树数据结构及相关操作
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct AVLTree
{
    unsigned int nData;    /*存储数据*/
    struct AVLTree* pLeft;    /*指向左子树*/
    struct AVLTree* pRight;    /*指向右子树*/
    int nHeight;    /*树的平衡度*/
}AVLTree;

/*插入操作*/
struct AVLTree* insert_tree(unsigned int nData, struct AVLTree* pNode);

/*查找操作，找到返回1，否则，返回0*/
int find_tree(unsigned int data, struct AVLTree* pRoot);

/*删除操作,删除所有节点*/
void delete_tree(struct AVLTree** ppRoot);

/*打印操作*/
void print_tree(struct AVLTree* pRoot);
#endif