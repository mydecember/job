typedef struct BBT  
{  
 int data;              //节点的数据域  
 int bf;                //平衡因子  
 BBT * lchild,*rchild;  //节点的左、右孩子指针  
}* B_Point,BBT;            //将B_Point定义为结构体指针  
B_Point Root;              //定义全树的树根指针全局变量  
//左旋转  
void BBT_L_Rotate(B_Point & root)            // root为需要旋转的子树树根指针   
{  
 B_Point rc=root->rchild;                 // 将rc指身树的树根的右子树  
 root->rchild=rc->lchild;                 // 将树的右子树的左子树挂到树根的右子树上  
 rc->lchild=root;                         // 将root所指树挂到rc的左子树上  
 root=rc;                                 //更新树根  
}  
// 右旋转  
void BBT_R_Rotate(B_Point & root)             // root为需要右旋的子树树根指针  
{  
 B_Point lc=root->lchild;                  //lc指向root的右子树根  
 root->lchild=lc->rchild;                  //lc的右子树连接到root的左子树上  
 lc->rchild =root;                         //root连接到lc的右子树  
 root=lc;                                  //更新树根      
}  
//左平衡处理  
void LeftBalance(B_Point & root)       
{  
 B_Point lc=root->lchild,rc=NULL;          //lc指向root的左子树  
 if(lc->bf==1)                             //LL型  
 {  
  root->bf=lc->bf=0;                    //更新平衡因子  
  BBT_R_Rotate(root);                   //root作为根进行右旋转  
 }  
 else if(lc->bf==-1)                       //LR型  
 {  
  rc=lc->rchild;                        //将rc指向lc的右子树  
  if(rc->bf==1)                         //检查rc的平衡因子，并做相应的处理  
  {  
   root->bf=-1;  
   lc->bf=0;  
  }  
  else if(rc->bf==0)  
  {  
   root->bf=0;  
   lc->bf=0;  
  }  
  else  
  {  
   root->bf =0;  
   lc->bf =1;  
  }  
  rc->bf=0;  
  BBT_L_Rotate(root->lchild);               //以root的左子树根结点为根进行左旋转处理  
  BBT_R_Rotate(root);                       //以root作为根进行旋转处理  
 }  
 else  //此情况只可能出现在删除中     此时lc->bf等于0        
 {//修改平衡因子  
  rc=lc->rchild;  
  if(rc->bf==1)  
  {  
   root->bf=-1;  
   lc->bf=1;  
   rc->bf=1;  
  }  
  else if(rc->bf==0)  
  {  
   root->bf=1;  
   lc->bf=1;  
   rc->bf=1;  
  }  
  else  
  {  
   root->bf =0;  
   lc->bf =2;//设为2方便后面识别  
   rc->bf=0;  
  }  
    
  BBT_L_Rotate(root->lchild);  
  BBT_R_Rotate(root);  
  if(root->lchild->bf==2)        //此时再追加一次旋转  
  {  
   root->lchild->bf=root->lchild->lchild->bf=0;  
   BBT_R_Rotate(root->lchild);  
  }  
 }  
}  
//右平衡处理  
void RightBalance(B_Point & root)         
{  
 B_Point rc=root->rchild,lc=NULL;  
 if(rc->bf==-1)                     //RR型  
 {  
  rc->bf=root->bf=0;  
  BBT_L_Rotate(root);  
 }  
 else if(rc->bf==1)                 //RL型  
 {  
  lc=rc->lchild;  
  if(lc->bf==1)  
  {  
   rc->bf=0;  
   root->bf =-1;  
  }  
  else if(lc->bf==0)  
  {  
   root->bf=rc->bf=0;  
  }  
  else  
  {  
   root->bf =1;  
   rc->bf =0;  
  }  
  lc->bf=0;  
  BBT_R_Rotate(root->rchild);  
  BBT_L_Rotate(root);  
 }  
 else //此情况只可能出现在删除过程中   此时rc->bf等于0  
 {  
  lc=rc->lchild;  
  if(lc->bf==1)                       //检查lc的平衡因子，并进行相应处理  
  {  
   rc->bf=-2;  
   root->bf =0;  
   lc->bf=0;  
  }  
  else if(lc->bf==0)  
  {  
   root->bf=0;  
   rc->bf=-1;  
   lc->bf=-1;  
  }  
  else  
  {  
   root->bf =1;  
   rc->bf =-1;  
  }  
    
  BBT_R_Rotate(root->rchild);  
  BBT_L_Rotate(root);  
  if(root->rchild->bf==-2)//此时由于树并不平等，须追加一次旋转  
  {  
   root->rchild->bf=root->rchild->rchild->bf=0;//更新平衡因子  
   BBT_L_Rotate(root->rchild);  
  }  
 }  
}  
  
// 插入操作  
bool BBT_Insert(B_Point & now,bool & taller,int data)   //now表示当前子树的根,taller为真时表示到目前为子树层数增加，为假则没增加  
{                                                       //插入成功返回真，否则返回假  
 bool result=false;                               //result表示插入的结果,插入成功为真，否则为假  
 if(!now)                                         //now指针为空时在当前指针处插入新节点  
 {  
  now=new BBT;                                 //新建一个节点  
  now->bf=0;                                   //节点初始化操作，平衡因子赋为0  
  now->data=data;                              //将待插入的数据置入新节点的数据域中  
  now->lchild=now->rchild=NULL;                //将新节点的左右子树指针置为空  
  taller=true;                                 //添加新节点，默认为增加子树的高度  
  return true;                                 //插入成功，返回真  
 }  
 else if(data<now->data)                          //当前待插入数据小于当前子树根的数据  
 {  
  result=BBT_Insert(now->lchild,taller,data);   //递归，以当前树根的左子树根为新子树树根调用插入函数  
  if(taller)                                    //判断taller的值，为真时插入操作一定成功，并且进入平衡处理  
  {                                             //检查插入前当前树根的平衡因子  
   if(now->bf==-1)                             
   {  
    now->bf=0;                            //插入后不改变此子树高度，无须进一步平衡处理，修改平衡因子即可  
    taller=false;                         //子树高不改变，taller置为假  
   }  
   else if(now->bf==0)  
   {  
    now->bf =1;                            //插入后子树高增加，但此子树的局部平衡没被破坏，修改平衡因子即可  
    taller=true;                           //树高增加，taller置为真  
   }  
   else  
   {  
    LeftBalance(now);                      //插入后此子树局部平衡被破坏，需调用左平衡处理函数使之平衡  
    taller=false;                          //平衡处理后此子树高度不会增加，taller置为假  
   }  
  }  
 }  
 else if(data>now->data)                             //待插入数据大于当前子树根节点数据  
 {  
  result=BBT_Insert(now->rchild,taller,data);     //以下同上  
  if(taller)  
  {  
   if(now->bf==-1)  
   {  
    RightBalance(now);  
    taller=false;  
   }  
   else if(now->bf==0)  
   {  
    now->bf=-1;  
    taller=true;  
   }  
   else  
   {  
    now->bf=0;  
    taller=false;  
   }  
  }  
 }  
 return result;                                       //返回插入情况  
}  
void BBT_Del(B_Point & root,int data,bool & shorter,bool & suc,bool & del,bool & leaf)  
{//suc表示删除成功，shorter表示子树高度减小与否，del表示在本次中删除,leaf表示删除的节点是否为叶子节点  
 B_Point p,f;  
 if(!root)                                         //root为空时表示未找到该数据，suc赋为假  
  suc=false;       
 else if(root->data==data)                         //如果待删除数据与当前子树根节点数据相等，即待删除节点为root  
 {  
  if(root->lchild==NULL&&root->rchild==NULL)    //检查是否为叶子节点  
  {  
   leaf=del=true;                            //将leaf、del赋为真，向上层传递删除节点信息  
   if(Root==root) Root=NULL;                 //如果删除的节点是全树的根节点，则将全树根节点指针置为空  
   delete root;                              //删除该节点  
   shorter=true;                             //当前子树高度减小  
  }  
  else                             //不是叶子节点  
  {  
   if(root->lchild==NULL)//左子树为空时  (左为空右一定不为空，否则就是叶子)  
   {  
    p=root;                  // 将p指向root  
    root=root->rchild;       // 将root的右子树挂到root上  
    delete(p);               // 删除p所指节点  
    shorter=true;            // 当前子树高度减小  
   }  
   else //左子树不为空时  
   {  
    p=f=root->lchild;         // 将p,f指向root的左孩子  
    while(p->rchild)          // 左转向右到底  
    {  
     f=p;                  //f为p的前驱  
     p=p->rchild;          //p向右子树走  
    }  
    if(p==f)                      //此时p没有右子树  
    {//将root的左子树根节点补上来做新的root,删除以前的root  
     p=root;                   //将p指向root  
     root=f;                   //将root指向f  
     root->rchild=p->rchild;   //将p的右子树挂到新root的右子树  
     if(p->bf==0)//检查原树根的平衡因子  
     {  
      shorter=false;        //当前树高度没有减小  
      root->bf=-1;          //更新当前树根的平衡因子  
     }  
     else if(p->bf==1)           
     {  
      shorter=true;         //当前树高度减小  
      root->bf=0;           //更新平衡因子  
     }  
     else  
     {  
      root->bf=p->bf-1;     //更新平衡因子  
         RightBalance(root);   //此时相当于右子树增加节点  
      shorter=true;         //当前树高度减小  
     }  
     delete p;                 //删除待删节点  
    }  
    else  
    {// 此时待删除节点与左子树最右边的节点更换，再删除最右边的节点  
     root->data=p->data;       //更换两节点的数据  
     f->rchild=p->lchild;      //将p的左子树挂到其前驱f的右子树上  
     delete p;                 //删除p所指的结点  
     if(f->bf==0)              //检查f平衡因子  
     {  
      shorter=false;        //当前以f为根的子树高没发生变化  
      f->bf=1;              //更新f的平衡因子  
     }  
     else if(f->bf==1)  
     {  
      LeftBalance(root->lchild);//当前以f为根的子树进行左平衡处理(相当于左边增加节点)  
      shorter=true;  
     }  
     else  
     {  
      shorter=true;           //以f 为根的子树平衡未被破坏，但高度减小  
      f->bf=0;                //更新f的平衡因子  
     }  
     if(shorter)                 //当以f 为根的子树树高减小时,进行平衡处理  
     {//此这程类似上述过程  
      if(root->bf==0)  
      {  
       shorter=false;  
       root->bf=-1;  
      }  
      else if(root->bf==1)  
      {  
       shorter=true;  
       root->bf=0;  
      }  
      else  
      {  
       RightBalance(root);//相当于右边增加  
       shorter=true;  
      }  
     }  
    }  
   }  
  }  
 }  
 else if(data<root->data)        //待删除的数据小于当前树根数据  
 {  
  BBT_Del(root->lchild,data,shorter,suc,del,leaf);   //递归，在以root左子树根中继续调用本函数  
  if(del&&leaf)                       //删除的是叶子节点  
  {  
   root->lchild=NULL;              //当前树根左子树指针置为空  
   del=false;                      //更新 del的值  
  }  
  if(shorter)                        //shorter为真，树高减小，分析平衡因子，进行平衡处理  
  {  
   if(root->bf==0)  
   {  
    root->bf=-1;  
    shorter=false;  
   }  
   else if(root->bf==1)  
   {  
    root->bf=0;  
    shorter=true;  
   }  
   else  
   {  
    RightBalance(root);  
    shorter=true;  
   }  
  }  
 }  
 else//待删除的数据大于当前树根数据  
 {  
  BBT_Del(root->rchild,data,shorter,suc,del,leaf);  
  if(del&&leaf)  
  {  
   del=false;  
   root->rchild=NULL;  
  }  
  if(shorter)  
  {  
   if(root->bf==0)  
   {  
    root->bf=1;  
    shorter=false;  
   }  
   else if(root->bf==1)  
   {  
    LeftBalance(root);//  
    shorter=true;  
   }  
   else  
   {  
    root->bf=0;  
    shorter=true;  
   }  
  }  
 }  
}  
 //查找平衡因子  
int Find_BF(B_Point root,int data)              
{  
 if(!root)  
  return 100;//100表示不存在,以用表示查找失败  
 if(data==root->data)    
  return root->bf;                        //找到该数据节点，返回平衡因子  
 else if(data<root->data)                    //否则递归调用  
  return Find_BF(root->lchild,data);  
 else return Find_BF(root->rchild,data);  
}  
//中序遍历  
void Traverse(B_Point root)  
{  
 if(root)//当前根节点不为空  
 {  
  Traverse(root->lchild);           //在左子树中递归  
  printf("%d ",root->data);         //显示当前节点为数据  
  Traverse(root->rchild);           //在右子树中递归  
 }  
}  
//获取树高  
void GetTreeHeight(B_Point root,int TreeHeight,int & MaxHeight)  
{  
 if(root)                                               //当前根节点不为空  
 {  
  TreeHeight++;                                      //树高加1  
  if(TreeHeight>MaxHeight) MaxHeight=TreeHeight;     //与树高最大值比较  
  GetTreeHeight(root->lchild,TreeHeight,MaxHeight);  //在左子树中递归  
  GetTreeHeight(root->rchild,TreeHeight,MaxHeight);  //在右子树中递归  
 }  
}  