#include "avl.h"


static int Max(int a, int b);
static int Height(struct AVLTree* pNode);

/*旋转操作*/
static struct AVLTree* SingleRotateWithLeft(struct AVLTree* pNode);
static struct AVLTree* SingleRotateWithRight(struct AVLTree* pNode);
static struct AVLTree* DoubleRotateWithLeft(struct AVLTree* pNode);
static struct AVLTree* DoubleRotateWithRight(struct AVLTree* pNode);

struct AVLTree* insert_tree(unsigned int nData, struct AVLTree* pNode)
{
    if (NULL == pNode)
    {
        pNode = (struct AVLTree*)xalloc(sizeof(struct AVLTree));
        pNode->nData = nData;
        pNode->nHeight = 0;
        pNode->pLeft = pNode->pRight = NULL;
    }
    else if (nData < pNode->nData)    /*插入到左子树中*/
    {
        pNode->pLeft = insert_tree(nData, pNode->pLeft);
        if (Height(pNode->pLeft) - Height(pNode->pRight) == 2)    /*AVL树不平衡*/
        {
            if (nData < pNode->pLeft->nData)
            {
                /*插入到了左子树左边, 做单旋转*/
                pNode = SingleRotateWithLeft(pNode);
            }
            else 
            {
                /*插入到了左子树右边, 做双旋转*/
                pNode = DoubleRotateWithLeft(pNode);
            }
        }
    }
    else if (nData > pNode->nData)    /*插入到右子树中*/
    {
        pNode->pRight = insert_tree(nData, pNode->pRight);
        if (Height(pNode->pRight) - Height(pNode->pLeft) == 2)    /*AVL树不平衡*/
        {
            if (nData > pNode->pRight->nData)
            {
                /*插入到了右子树右边, 做单旋转*/
                pNode = SingleRotateWithRight(pNode);
            }
            else 
            {
                /*插入到了右子树左边, 做双旋转*/
                pNode = DoubleRotateWithRight(pNode);
            }
        }
    }

    pNode->nHeight = Max(Height(pNode->pLeft), Height(pNode->pRight)) + 1;

    return pNode;
}


/*删除树*/
void delete_tree(struct AVLTree** ppRoot)
{
    if (NULL == ppRoot || NULL == *ppRoot)
        return;

    delete_tree(&((*ppRoot)->pLeft));
    delete_tree(&((*ppRoot)->pRight));
    xfree(*ppRoot);
    *ppRoot = NULL;
}

/*中序遍历打印树的所有结点, 因为左结点 < 父结点 < 右结点, 因此打印出来数据的大小是递增的*/
void print_tree(struct AVLTree* pRoot)
{
    if (NULL == pRoot)
        return;

    static int n = 0;


    print_tree(pRoot->pLeft);
    printf("[%d]nData = %u\n", ++n, pRoot->nData);
    print_tree(pRoot->pRight);
}

/*
 *查找操作，找到返回1，否则，返回0
 *data是待查找的数据
 *pRoot:avl树的指针
 */
int find_tree(unsigned int data, struct AVLTree* pRoot)
{
    static int k=1;    /*查找次数*/
    if (NULL == pRoot)
    {
        printf("not find %d times\n", k);
        return 0;
    }

    if(data == pRoot->nData)
    {
        printf("find:%d times\n", k);
        return 1;
    }
    else if(data < pRoot->nData)
    {
        ++k;
        return find_tree(data, pRoot->pLeft);
    }
    else if(data > pRoot->nData)
    {
        ++k;
        return find_tree(data, pRoot->pRight);
    }
}

static int Max(int a, int b)
{
    return (a > b ? a : b);
}

/*返回节点的平衡度*/
static int Height(struct AVLTree* pNode)
{
    if (NULL == pNode)
        return -1;

    return pNode->nHeight;
}

/********************************************************************
      pNode pNode->pLeft 
      / \
  pNode->pLeft ==> pNode
      \     /
  pNode->pLeft->pRight pNode->pLeft->pRight
 *********************************************************************/
static struct AVLTree* SingleRotateWithLeft(struct AVLTree* pNode)
{
    struct AVLTree* pNode1;

    pNode1 = pNode->pLeft;
    pNode->pLeft = pNode1->pRight;
    pNode1->pRight = pNode;

    /*结点的位置变了, 要更新结点的高度值*/
    pNode->nHeight = Max(Height(pNode->pLeft), Height(pNode->pRight)) + 1;
    pNode1->nHeight = Max(Height(pNode1->pLeft), pNode->nHeight) + 1;

    return pNode1;
}

/********************************************************************
  pNode pNode->pRight
  \ /
  pNode->pRight ==> pNode 
  / \
  pNode->pRight->pLeft pNode->pRight->pLeft
 *********************************************************************/
static struct AVLTree* SingleRotateWithRight(struct AVLTree* pNode)
{
    struct AVLTree* pNode1;

    pNode1 = pNode->pRight;
    pNode->pRight = pNode1->pLeft;
    pNode1->pLeft = pNode;

    /*结点的位置变了, 要更新结点的高度值*/
    pNode->nHeight = Max(Height(pNode->pLeft), Height(pNode->pRight)) + 1;
    pNode1->nHeight = Max(Height(pNode1->pRight), pNode->nHeight) + 1;

    return pNode1;
}

static struct AVLTree* DoubleRotateWithLeft(struct AVLTree* pNode)
{
    pNode->pLeft = SingleRotateWithRight(pNode->pLeft);

    return SingleRotateWithLeft(pNode);
}

static struct AVLTree* DoubleRotateWithRight(struct AVLTree* pNode)
{
    pNode->pRight = SingleRotateWithLeft(pNode->pRight);

    return SingleRotateWithRight(pNode);
}



#include <stdio.h>
#include <time.h>
#include "avl.h"
int main()
{
    int i,j;
    AVLTree* pRoot = NULL;

    srand((unsigned int)time(NULL));
    
    for (i = 0; i < 10; ++i)
    {
            j = rand();
            printf("%d\n", j);
        pRoot = insert_tree(j, pRoot);
    }

    print_tree(pRoot);

    delete_tree(&pRoot);

    return 0;
}