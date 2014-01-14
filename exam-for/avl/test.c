#include <stdio.h>  
#include <stdlib.h>  
//平衡因子  
#define LEFT_HIGH    1  
#define EVEN_HIGH    0  
#define RIGHT_HIGH  -1  
//每次插入或删除，只有一颗最小子树不平衡  
#define BALANCE      0  
  
typedef char Key_t;  
  
typedef struct treeNode  
{  
    Key_t key;  
    char bf;  
    struct treeNode *left, *right;  
    struct treeNode *parent;  
}Tnode;  
  
int balance;//不得已定义的全局变量，用于判断树是否已经平衡  
//查到指定key的Tnode结点  
Tnode *search(Tnode *root, Key_t key)  
{  
    if(NULL == root)  
        return NULL;  
    if(key > root->key)  
        return search(root->right, key);  
    else if(key < root->key)  
        return search(root->left, key);  
    else   
        return root;  
}  
//查找一个P节点的前驱节点  
Tnode *search_former(Tnode *p)  
{  
    if(NULL == p)  
        return p;  
//P结点有左子树，此左子树下的最右子树便是P的前驱  
    if(p->left){  
        p = p->left;  
        while(p->right)  
            p = p->right;  
        return p;  
    }else{  
//P没有左子树，向上查找到，第一个开始折向右边的结点便是P的前驱  
        while(p->parent){  
            if(p->parent->right == p)  
                break;  
            p = p->parent;  
        }  
        return p->parent;  
    }  
}  
//查找一个P节点的后继节点  
Tnode *search_latter(Tnode *p)  
{  
    if(NULL == p)  
        return p;  
//P结点有右子树，此右子树下的最左子树便是P的后继  
    if(p->right){  
        p = p->right;  
        while(p->left)  
            p = p->left;  
        return p;  
    }else{  
//P没有右子树，向上查找到，第一个开始折向左边的结点便是P的后继  
        while(p->parent){  
            if(p->parent->left == p)  
                break;  
            p = p->parent;  
        }  
        return p->parent;  
    }  
}  
//根节点为-2，即右子树插入或左子树有删除导致的不平衡，左旋转  
void turn_left(Tnode **root)  
{  
    Tnode *right = (*root)->right;  
//旋转后处理旋转节点的父节点  
    right->parent = (*root)->parent;  
    (*root)->parent = right;  
    if(right->left != NULL)  
        right->left->parent = (*root);  
//左旋操作  
    (*root)->right = right->left;   
    right->left = (*root);  
    (*root) = right;  
    return;  
}  
//根节点为-2，即右子树插入或左子树有删除导致的不平衡，左旋转  
void turn_right(Tnode **root)  
{  
    Tnode *left = (*root)->left;  
//旋转后处理旋转节点的父节点  
    left->parent = (*root)->parent;  
    (*root)->parent = left;  
    if(left->right != NULL)  
        left->right->parent = (*root);  
//右旋操作  
    (*root)->left = left->right;  
    left->right = (*root);  
    (*root) = left;  
    return;  
}  
//左平衡操作  
void left_balance(Tnode **root)  
{  
      
   Tnode *left = (*root)->left;   
   Tnode *lright;   
  
   switch(left->bf){  
//root的bf为1，若root的left为1时，即root为2，然后进行右旋，此时3个节点像符号 /，L型  
       case LEFT_HIGH:  
           (*root)->bf = left->bf = EVEN_HIGH;  
           turn_right(root);  
         break;  
//root的bf为1，若root的left也为-1时，即root为2，左高，此时3个节点像符号 <，LR型  
       case RIGHT_HIGH:  
           lright = left->right;  
//分成3种情况来处理3个节点的平衡因子  
           switch(lright->bf){  
               case LEFT_HIGH:  
                   (*root)->bf = RIGHT_HIGH;  
                   left->bf = EVEN_HIGH;  
                 break;  
               case EVEN_HIGH:  
                    (*root)->bf = left->bf = EVEN_HIGH;  
                 break;  
               case RIGHT_HIGH:  
                    (*root)->bf = EVEN_HIGH;  
                    left->bf = LEFT_HIGH;  
                 break;  
           }  
           lright->bf = EVEN_HIGH;  
//左旋然后右旋，即LR型  
           turn_left(&(*root)->left);  
           turn_right(root);  
          break;  
   }  
  
}  
//右平衡操作  
void right_balance(Tnode **root)  
{   
   Tnode *right = (*root)->right;   
   Tnode *rleft;   
  
   switch(right->bf){  
//root的bf为-1，若root的right为1时，即root为-2，然后进行右左旋，此时3个节点像符号 <，RL型  
       case LEFT_HIGH:  
           rleft = right->left;  
//分成3种情况来处理3个节点的平衡因子  
           switch(rleft->bf){  
               case LEFT_HIGH:  
                   (*root)->bf = EVEN_HIGH;  
                   right->bf = RIGHT_HIGH;  
                 break;  
               case EVEN_HIGH:  
                    (*root)->bf = right->bf = EVEN_HIGH;  
                 break;  
               case RIGHT_HIGH:  
                    (*root)->bf = LEFT_HIGH;  
                    right->bf = EVEN_HIGH;  
                 break;  
           }  
           rleft->bf = EVEN_HIGH;  
           turn_right(&(*root)->right);  
           turn_left(root);  
         break;  
//root的bf为-1，若root的right为-1时，即root为-2，然后进行左旋，此时3个节点像符号 \，R型  
       case RIGHT_HIGH:  
          (*root)->bf = right->bf = EVEN_HIGH;  
           turn_left(root);  
         break;  
   }  
}  
//dele_AVL_node删除节点中调用，用于删除节点  
void part_of_dele(Tnode **root, Tnode *p)  
{  
//没有左右子节点时，直接删除P结点，要将在P的父指向P的指针要置空  
    if(!p->left && !p->right){  
//如果P节点的父节点不为空，即P不是根节点  
        if(p->parent){  
            if(p == p->parent->left)  
                p->parent->left = NULL;  
            else if(p == p->parent->right)  
                p->parent->right = NULL;  
        }else{  
            *root = NULL;  
        }  
    }  
//P有左节点，没有右节点时，分三种情况  
    else if(p->left && !p->right){  
//P为根节点，设置根节点为p->left  
        if(!p->parent){  
            *root = p->left;  
        }  
 //P为父节点的左分支，将p->left的父节点指向P的父节点，p父节点左分支指向p->left  
        else if(p == p->parent->left){  
            p->parent->left = p->left;  
            p->left->parent = p->parent;  
        }  
//P为父节点的右分支，将p->left的父节点指向P的父节点，p父节点右分支指向p->left  
        else if(p == p->parent->right){  
            p->parent->right = p->left;  
            p->left->parent = p->parent;  
        }  
    }  
//P有右节点，没有左节点时，分三种情况  
    else if(!p->left && p->right){  
        if(!p->parent){  
            *root = p->right;  
        }  
//P为父节点的左分支，将p->right的父节点指向P的父节点，p父节点左分支指向p->right  
        else if(p == p->parent->left){  
            p->parent->left = p->right;  
            p->right->parent = p->parent;  
        }  
//P为父节点的右分支，将p->right的父节点指向P的父节点，p父节点右分支指向p->right  
        else if(p == p->parent->right){  
            p->parent->right = p->right;  
            p->right->parent = p->parent;  
        }  
    }  
    free(p);  
    return;  
}  
  
//删除平衡二叉树节点  
void dele_AVL_node(Tnode **root, Key_t key)  
{  
//如果*root为NULL,即没有找到对应要删除的KEY值节点  
    if(NULL == *root){  
        balance = BALANCE;  
        return;  
    }  
//若key小于root，则在左分支中查找  
    else if(key < (*root)->key){  
        dele_AVL_node(&(*root)->left, key);  
//判断是否失衡  
        if(balance)  
//删除操作的平衡操作  
            switch((*root)->bf){  
                case LEFT_HIGH:  
                    (*root)->bf = EVEN_HIGH;  
                    balance = !BALANCE;  
                    break;  
                case EVEN_HIGH:  
                    (*root)->bf = RIGHT_HIGH;  
                    balance = BALANCE;  
                    break;  
                case RIGHT_HIGH:  
                    right_balance(root);  
                    balance = BALANCE;  
                    break;  
            }  
    }  
//若key大于root，则在右分支中查找  
    else if((*root)->key < key){  
        dele_AVL_node(&(*root)->right, key);  
//判断是否失衡  
        if(balance)  
//删除操作的平衡操作  
            switch((*root)->bf){  
                case LEFT_HIGH:  
                    left_balance(root);  
                    balance = BALANCE;  
                    break;  
                case EVEN_HIGH:  
                    (*root)->bf = LEFT_HIGH;  
                    balance = BALANCE;  
                    break;  
                case RIGHT_HIGH:  
                    (*root)->bf = EVEN_HIGH;  
                    balance = !BALANCE;  
                    break;  
        }  
    }  
//查到要删除的节点  
    else{  
//若节点有左右子树，刚找到此节点的前驱，对此前驱进行递归删除，并将前驱值覆盖删除的节点值  
        if((*root)->left && (*root)->right){  
            Tnode *q = search_former(*root);  
            Tnode *ptr = *root;  
            Key_t bak = q->key;  
            dele_AVL_node(root, q->key);  
            ptr->key = bak;  
        }   
//没有左右子树时，则直接删除节点，并告知树失衡  
        else {  
            part_of_dele(&(*root)->parent, *root);  
            balance = !BALANCE;  
        }  
    }  
  
    return;  
}  
//插入操作的递归及平衡部分  
void part_of_insert(Tnode **root, Tnode *p)  
{  
//*root为NULL时，代表找到要插入的位置，设置失衡  
    if(NULL == *root){  
        p->parent = NULL;  
        *root = p;  
        balance = !BALANCE;  
        return;  
    }  
//p->key小于root->key，刚在左分支查找  
    else if(p->key < (*root)->key){  
//找到要插入的位置，设置失衡，下面会接着进行平衡操作  
        if(NULL == (*root)->left){   
            p->parent = *root;  
            (*root)->left = p;  
            balance = !BALANCE;  
        }   
//有左支树，则接着在左子树查找  
        else{  
            part_of_insert(&(*root)->left, p);  
        }  
//插入时的平衡操作  
        if(balance)  
            switch((*root)->bf){  
                case LEFT_HIGH:  
                    left_balance(root);  
                    balance = BALANCE;  
                    break;  
                case EVEN_HIGH:  
                    (*root)->bf = LEFT_HIGH;  
                    balance = !BALANCE;  
                    break;  
                case RIGHT_HIGH:  
                    (*root)->bf = EVEN_HIGH;  
                    balance = BALANCE;  
                    break;  
  
            }  
        return;  
    }  
//p->key大于root->key，刚在右分支查找  
    else if((*root)->key <= p->key){  
//找到要插入的位置，设置失衡，下面会接着进行平衡操作  
        if(NULL == (*root)->right){  
            p->parent = *root;  
            (*root)->right = p;  
            balance = !BALANCE;  
        }  
//有左支树，则接着在左子树查找  
        else{  
            part_of_insert(&(*root)->right, p);  
        }  
//插入时的平衡操作  
        if(balance)  
            switch((*root)->bf){  
                case LEFT_HIGH:  
                    (*root)->bf = EVEN_HIGH;  
                    balance = BALANCE;  
                    break;  
                case EVEN_HIGH:  
                    (*root)->bf = RIGHT_HIGH;  
                    balance = !BALANCE;  
                    break;  
                case RIGHT_HIGH:  
                    right_balance(root);  
                    balance = BALANCE;  
                    break;  
            }  
        return;  
    }  
  
    return;  
}  
//节点插入函数  
int insert_AVL_node(Tnode **root, Key_t key)  
{  
    Tnode *p = (Tnode *)malloc(sizeof(Tnode));  
    if(NULL == p)  return -1;  
  
    p->key = key;  
    p->left = p->right = NULL;  
//新插入的节点是平衡的  
    p->bf = EVEN_HIGH;  
    balance = !BALANCE;  
  
    part_of_insert(root, p);  
  
    return 0;  
}  
//后序摧毁二叉树  
void destroy_tree(Tnode **root)  
{  
    if(!*root)  
        return;  
    destroy_tree(&(*root)->left);  
    destroy_tree(&(*root)->right);  
    free(*root);  
    *root = NULL;  
    return;  
}  
//通过数组生成平衡二叉树,root根节点,table数组指针,count数组大小  
int create_AVL(Tnode **root, Key_t *table, int counts)  
{  
    int i;  
    int ret = -1;  
      
    *root = NULL;  
    for(i = 0; i < counts; ++i){  
        ret = insert_AVL_node(root, table[i]);  
        if(ret < 0)  
            break;  
    }  
  
    return ret;  
}  
//中序遍历二叉树  
void mid_order(Tnode *root)  
{  
    if(root == NULL)  
        return;  
  
    mid_order(root->left);  
    printf("|%d[%d] p:%d| ", root->key, root->bf, root->parent ? root->parent->key:-1);  
    mid_order(root->right);  
  
    return;  
}  
//树深度  
int depth_of_tree(Tnode *root)  
{  
    int h, lh, rh;  
  
    if(root == NULL)  
        h = 0;  
    else{  
        lh = depth_of_tree(root->left);  
        rh = depth_of_tree(root->right);  
        if(lh > rh)  
            h = lh + 1;  
        else  
            h = rh + 1;  
    }  
  
    return h;  
}  
  
int main()  
{  
    Key_t table[] = {4,5,7,2,1,3,6};  
    Tnode *root = NULL;  
    int h;  
  
    create_AVL(&root, table, sizeof(table)/sizeof(table[0]));  
   // insert_AVL_node(&root, 4);  
   // dele_AVL_node(&root, 2);  
   // dele_AVL_node(&root, 6);  
#if 1  
    dele_AVL_node(&root, 4);  
    mid_order(root);  
    printf("\n");  
    dele_AVL_node(&root, 1);  
    mid_order(root);  
    printf("\n");  
    dele_AVL_node(&root, 6);  
    mid_order(root);  
    printf("\n");  
#endif  
    dele_AVL_node(&root, 3);  
    mid_order(root);  
    printf("\n");  
    h = depth_of_tree(root);  
    printf("depth:%d\n", h);  
    destroy_tree(&root);  
    h = depth_of_tree(root);  
    printf("depth:%d\n", h);  
    return 0;  
}   