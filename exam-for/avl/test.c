#include <stdio.h>  
#include <stdlib.h>  
//ƽ������  
#define LEFT_HIGH    1  
#define EVEN_HIGH    0  
#define RIGHT_HIGH  -1  
//ÿ�β����ɾ����ֻ��һ����С������ƽ��  
#define BALANCE      0  
  
typedef char Key_t;  
  
typedef struct treeNode  
{  
    Key_t key;  
    char bf;  
    struct treeNode *left, *right;  
    struct treeNode *parent;  
}Tnode;  
  
int balance;//�����Ѷ����ȫ�ֱ����������ж����Ƿ��Ѿ�ƽ��  
//�鵽ָ��key��Tnode���  
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
//����һ��P�ڵ��ǰ���ڵ�  
Tnode *search_former(Tnode *p)  
{  
    if(NULL == p)  
        return p;  
//P����������������������µ�������������P��ǰ��  
    if(p->left){  
        p = p->left;  
        while(p->right)  
            p = p->right;  
        return p;  
    }else{  
//Pû�������������ϲ��ҵ�����һ����ʼ�����ұߵĽ�����P��ǰ��  
        while(p->parent){  
            if(p->parent->right == p)  
                break;  
            p = p->parent;  
        }  
        return p->parent;  
    }  
}  
//����һ��P�ڵ�ĺ�̽ڵ�  
Tnode *search_latter(Tnode *p)  
{  
    if(NULL == p)  
        return p;  
//P����������������������µ�������������P�ĺ��  
    if(p->right){  
        p = p->right;  
        while(p->left)  
            p = p->left;  
        return p;  
    }else{  
//Pû�������������ϲ��ҵ�����һ����ʼ������ߵĽ�����P�ĺ��  
        while(p->parent){  
            if(p->parent->left == p)  
                break;  
            p = p->parent;  
        }  
        return p->parent;  
    }  
}  
//���ڵ�Ϊ-2�����������������������ɾ�����µĲ�ƽ�⣬����ת  
void turn_left(Tnode **root)  
{  
    Tnode *right = (*root)->right;  
//��ת������ת�ڵ�ĸ��ڵ�  
    right->parent = (*root)->parent;  
    (*root)->parent = right;  
    if(right->left != NULL)  
        right->left->parent = (*root);  
//��������  
    (*root)->right = right->left;   
    right->left = (*root);  
    (*root) = right;  
    return;  
}  
//���ڵ�Ϊ-2�����������������������ɾ�����µĲ�ƽ�⣬����ת  
void turn_right(Tnode **root)  
{  
    Tnode *left = (*root)->left;  
//��ת������ת�ڵ�ĸ��ڵ�  
    left->parent = (*root)->parent;  
    (*root)->parent = left;  
    if(left->right != NULL)  
        left->right->parent = (*root);  
//��������  
    (*root)->left = left->right;  
    left->right = (*root);  
    (*root) = left;  
    return;  
}  
//��ƽ�����  
void left_balance(Tnode **root)  
{  
      
   Tnode *left = (*root)->left;   
   Tnode *lright;   
  
   switch(left->bf){  
//root��bfΪ1����root��leftΪ1ʱ����rootΪ2��Ȼ�������������ʱ3���ڵ������ /��L��  
       case LEFT_HIGH:  
           (*root)->bf = left->bf = EVEN_HIGH;  
           turn_right(root);  
         break;  
//root��bfΪ1����root��leftҲΪ-1ʱ����rootΪ2����ߣ���ʱ3���ڵ������ <��LR��  
       case RIGHT_HIGH:  
           lright = left->right;  
//�ֳ�3�����������3���ڵ��ƽ������  
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
//����Ȼ����������LR��  
           turn_left(&(*root)->left);  
           turn_right(root);  
          break;  
   }  
  
}  
//��ƽ�����  
void right_balance(Tnode **root)  
{   
   Tnode *right = (*root)->right;   
   Tnode *rleft;   
  
   switch(right->bf){  
//root��bfΪ-1����root��rightΪ1ʱ����rootΪ-2��Ȼ���������������ʱ3���ڵ������ <��RL��  
       case LEFT_HIGH:  
           rleft = right->left;  
//�ֳ�3�����������3���ڵ��ƽ������  
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
//root��bfΪ-1����root��rightΪ-1ʱ����rootΪ-2��Ȼ�������������ʱ3���ڵ������ \��R��  
       case RIGHT_HIGH:  
          (*root)->bf = right->bf = EVEN_HIGH;  
           turn_left(root);  
         break;  
   }  
}  
//dele_AVL_nodeɾ���ڵ��е��ã�����ɾ���ڵ�  
void part_of_dele(Tnode **root, Tnode *p)  
{  
//û�������ӽڵ�ʱ��ֱ��ɾ��P��㣬Ҫ����P�ĸ�ָ��P��ָ��Ҫ�ÿ�  
    if(!p->left && !p->right){  
//���P�ڵ�ĸ��ڵ㲻Ϊ�գ���P���Ǹ��ڵ�  
        if(p->parent){  
            if(p == p->parent->left)  
                p->parent->left = NULL;  
            else if(p == p->parent->right)  
                p->parent->right = NULL;  
        }else{  
            *root = NULL;  
        }  
    }  
//P����ڵ㣬û���ҽڵ�ʱ�����������  
    else if(p->left && !p->right){  
//PΪ���ڵ㣬���ø��ڵ�Ϊp->left  
        if(!p->parent){  
            *root = p->left;  
        }  
 //PΪ���ڵ�����֧����p->left�ĸ��ڵ�ָ��P�ĸ��ڵ㣬p���ڵ����ָ֧��p->left  
        else if(p == p->parent->left){  
            p->parent->left = p->left;  
            p->left->parent = p->parent;  
        }  
//PΪ���ڵ���ҷ�֧����p->left�ĸ��ڵ�ָ��P�ĸ��ڵ㣬p���ڵ��ҷ�ָ֧��p->left  
        else if(p == p->parent->right){  
            p->parent->right = p->left;  
            p->left->parent = p->parent;  
        }  
    }  
//P���ҽڵ㣬û����ڵ�ʱ�����������  
    else if(!p->left && p->right){  
        if(!p->parent){  
            *root = p->right;  
        }  
//PΪ���ڵ�����֧����p->right�ĸ��ڵ�ָ��P�ĸ��ڵ㣬p���ڵ����ָ֧��p->right  
        else if(p == p->parent->left){  
            p->parent->left = p->right;  
            p->right->parent = p->parent;  
        }  
//PΪ���ڵ���ҷ�֧����p->right�ĸ��ڵ�ָ��P�ĸ��ڵ㣬p���ڵ��ҷ�ָ֧��p->right  
        else if(p == p->parent->right){  
            p->parent->right = p->right;  
            p->right->parent = p->parent;  
        }  
    }  
    free(p);  
    return;  
}  
  
//ɾ��ƽ��������ڵ�  
void dele_AVL_node(Tnode **root, Key_t key)  
{  
//���*rootΪNULL,��û���ҵ���ӦҪɾ����KEYֵ�ڵ�  
    if(NULL == *root){  
        balance = BALANCE;  
        return;  
    }  
//��keyС��root���������֧�в���  
    else if(key < (*root)->key){  
        dele_AVL_node(&(*root)->left, key);  
//�ж��Ƿ�ʧ��  
        if(balance)  
//ɾ��������ƽ�����  
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
//��key����root�������ҷ�֧�в���  
    else if((*root)->key < key){  
        dele_AVL_node(&(*root)->right, key);  
//�ж��Ƿ�ʧ��  
        if(balance)  
//ɾ��������ƽ�����  
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
//�鵽Ҫɾ���Ľڵ�  
    else{  
//���ڵ����������������ҵ��˽ڵ��ǰ�����Դ�ǰ�����еݹ�ɾ��������ǰ��ֵ����ɾ���Ľڵ�ֵ  
        if((*root)->left && (*root)->right){  
            Tnode *q = search_former(*root);  
            Tnode *ptr = *root;  
            Key_t bak = q->key;  
            dele_AVL_node(root, q->key);  
            ptr->key = bak;  
        }   
//û����������ʱ����ֱ��ɾ���ڵ㣬����֪��ʧ��  
        else {  
            part_of_dele(&(*root)->parent, *root);  
            balance = !BALANCE;  
        }  
    }  
  
    return;  
}  
//��������ĵݹ鼰ƽ�ⲿ��  
void part_of_insert(Tnode **root, Tnode *p)  
{  
//*rootΪNULLʱ�������ҵ�Ҫ�����λ�ã�����ʧ��  
    if(NULL == *root){  
        p->parent = NULL;  
        *root = p;  
        balance = !BALANCE;  
        return;  
    }  
//p->keyС��root->key���������֧����  
    else if(p->key < (*root)->key){  
//�ҵ�Ҫ�����λ�ã�����ʧ�⣬�������Ž���ƽ�����  
        if(NULL == (*root)->left){   
            p->parent = *root;  
            (*root)->left = p;  
            balance = !BALANCE;  
        }   
//����֧���������������������  
        else{  
            part_of_insert(&(*root)->left, p);  
        }  
//����ʱ��ƽ�����  
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
//p->key����root->key�������ҷ�֧����  
    else if((*root)->key <= p->key){  
//�ҵ�Ҫ�����λ�ã�����ʧ�⣬�������Ž���ƽ�����  
        if(NULL == (*root)->right){  
            p->parent = *root;  
            (*root)->right = p;  
            balance = !BALANCE;  
        }  
//����֧���������������������  
        else{  
            part_of_insert(&(*root)->right, p);  
        }  
//����ʱ��ƽ�����  
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
//�ڵ���뺯��  
int insert_AVL_node(Tnode **root, Key_t key)  
{  
    Tnode *p = (Tnode *)malloc(sizeof(Tnode));  
    if(NULL == p)  return -1;  
  
    p->key = key;  
    p->left = p->right = NULL;  
//�²���Ľڵ���ƽ���  
    p->bf = EVEN_HIGH;  
    balance = !BALANCE;  
  
    part_of_insert(root, p);  
  
    return 0;  
}  
//����ݻٶ�����  
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
//ͨ����������ƽ�������,root���ڵ�,table����ָ��,count�����С  
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
//�������������  
void mid_order(Tnode *root)  
{  
    if(root == NULL)  
        return;  
  
    mid_order(root->left);  
    printf("|%d[%d] p:%d| ", root->key, root->bf, root->parent ? root->parent->key:-1);  
    mid_order(root->right);  
  
    return;  
}  
//�����  
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