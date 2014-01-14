typedef struct BBT  
{  
 int data;              //�ڵ��������  
 int bf;                //ƽ������  
 BBT * lchild,*rchild;  //�ڵ�����Һ���ָ��  
}* B_Point,BBT;            //��B_Point����Ϊ�ṹ��ָ��  
B_Point Root;              //����ȫ��������ָ��ȫ�ֱ���  
//����ת  
void BBT_L_Rotate(B_Point & root)            // rootΪ��Ҫ��ת����������ָ��   
{  
 B_Point rc=root->rchild;                 // ��rcָ������������������  
 root->rchild=rc->lchild;                 // ���������������������ҵ���������������  
 rc->lchild=root;                         // ��root��ָ���ҵ�rc����������  
 root=rc;                                 //��������  
}  
// ����ת  
void BBT_R_Rotate(B_Point & root)             // rootΪ��Ҫ��������������ָ��  
{  
 B_Point lc=root->lchild;                  //lcָ��root����������  
 root->lchild=lc->rchild;                  //lc�����������ӵ�root����������  
 lc->rchild =root;                         //root���ӵ�lc��������  
 root=lc;                                  //��������      
}  
//��ƽ�⴦��  
void LeftBalance(B_Point & root)       
{  
 B_Point lc=root->lchild,rc=NULL;          //lcָ��root��������  
 if(lc->bf==1)                             //LL��  
 {  
  root->bf=lc->bf=0;                    //����ƽ������  
  BBT_R_Rotate(root);                   //root��Ϊ����������ת  
 }  
 else if(lc->bf==-1)                       //LR��  
 {  
  rc=lc->rchild;                        //��rcָ��lc��������  
  if(rc->bf==1)                         //���rc��ƽ�����ӣ�������Ӧ�Ĵ���  
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
  BBT_L_Rotate(root->lchild);               //��root�������������Ϊ����������ת����  
  BBT_R_Rotate(root);                       //��root��Ϊ��������ת����  
 }  
 else  //�����ֻ���ܳ�����ɾ����     ��ʱlc->bf����0        
 {//�޸�ƽ������  
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
   lc->bf =2;//��Ϊ2�������ʶ��  
   rc->bf=0;  
  }  
    
  BBT_L_Rotate(root->lchild);  
  BBT_R_Rotate(root);  
  if(root->lchild->bf==2)        //��ʱ��׷��һ����ת  
  {  
   root->lchild->bf=root->lchild->lchild->bf=0;  
   BBT_R_Rotate(root->lchild);  
  }  
 }  
}  
//��ƽ�⴦��  
void RightBalance(B_Point & root)         
{  
 B_Point rc=root->rchild,lc=NULL;  
 if(rc->bf==-1)                     //RR��  
 {  
  rc->bf=root->bf=0;  
  BBT_L_Rotate(root);  
 }  
 else if(rc->bf==1)                 //RL��  
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
 else //�����ֻ���ܳ�����ɾ��������   ��ʱrc->bf����0  
 {  
  lc=rc->lchild;  
  if(lc->bf==1)                       //���lc��ƽ�����ӣ���������Ӧ����  
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
  if(root->rchild->bf==-2)//��ʱ����������ƽ�ȣ���׷��һ����ת  
  {  
   root->rchild->bf=root->rchild->rchild->bf=0;//����ƽ������  
   BBT_L_Rotate(root->rchild);  
  }  
 }  
}  
  
// �������  
bool BBT_Insert(B_Point & now,bool & taller,int data)   //now��ʾ��ǰ�����ĸ�,tallerΪ��ʱ��ʾ��ĿǰΪ�����������ӣ�Ϊ����û����  
{                                                       //����ɹ������棬���򷵻ؼ�  
 bool result=false;                               //result��ʾ����Ľ��,����ɹ�Ϊ�棬����Ϊ��  
 if(!now)                                         //nowָ��Ϊ��ʱ�ڵ�ǰָ�봦�����½ڵ�  
 {  
  now=new BBT;                                 //�½�һ���ڵ�  
  now->bf=0;                                   //�ڵ��ʼ��������ƽ�����Ӹ�Ϊ0  
  now->data=data;                              //������������������½ڵ����������  
  now->lchild=now->rchild=NULL;                //���½ڵ����������ָ����Ϊ��  
  taller=true;                                 //����½ڵ㣬Ĭ��Ϊ���������ĸ߶�  
  return true;                                 //����ɹ���������  
 }  
 else if(data<now->data)                          //��ǰ����������С�ڵ�ǰ������������  
 {  
  result=BBT_Insert(now->lchild,taller,data);   //�ݹ飬�Ե�ǰ��������������Ϊ�������������ò��뺯��  
  if(taller)                                    //�ж�taller��ֵ��Ϊ��ʱ�������һ���ɹ������ҽ���ƽ�⴦��  
  {                                             //������ǰ��ǰ������ƽ������  
   if(now->bf==-1)                             
   {  
    now->bf=0;                            //����󲻸ı�������߶ȣ������һ��ƽ�⴦���޸�ƽ�����Ӽ���  
    taller=false;                         //�����߲��ı䣬taller��Ϊ��  
   }  
   else if(now->bf==0)  
   {  
    now->bf =1;                            //��������������ӣ����������ľֲ�ƽ��û���ƻ����޸�ƽ�����Ӽ���  
    taller=true;                           //�������ӣ�taller��Ϊ��  
   }  
   else  
   {  
    LeftBalance(now);                      //�����������ֲ�ƽ�ⱻ�ƻ����������ƽ�⴦����ʹ֮ƽ��  
    taller=false;                          //ƽ�⴦���������߶Ȳ������ӣ�taller��Ϊ��  
   }  
  }  
 }  
 else if(data>now->data)                             //���������ݴ��ڵ�ǰ�������ڵ�����  
 {  
  result=BBT_Insert(now->rchild,taller,data);     //����ͬ��  
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
 return result;                                       //���ز������  
}  
void BBT_Del(B_Point & root,int data,bool & shorter,bool & suc,bool & del,bool & leaf)  
{//suc��ʾɾ���ɹ���shorter��ʾ�����߶ȼ�С���del��ʾ�ڱ�����ɾ��,leaf��ʾɾ���Ľڵ��Ƿ�ΪҶ�ӽڵ�  
 B_Point p,f;  
 if(!root)                                         //rootΪ��ʱ��ʾδ�ҵ������ݣ�suc��Ϊ��  
  suc=false;       
 else if(root->data==data)                         //�����ɾ�������뵱ǰ�������ڵ�������ȣ�����ɾ���ڵ�Ϊroot  
 {  
  if(root->lchild==NULL&&root->rchild==NULL)    //����Ƿ�ΪҶ�ӽڵ�  
  {  
   leaf=del=true;                            //��leaf��del��Ϊ�棬���ϲ㴫��ɾ���ڵ���Ϣ  
   if(Root==root) Root=NULL;                 //���ɾ���Ľڵ���ȫ���ĸ��ڵ㣬��ȫ�����ڵ�ָ����Ϊ��  
   delete root;                              //ɾ���ýڵ�  
   shorter=true;                             //��ǰ�����߶ȼ�С  
  }  
  else                             //����Ҷ�ӽڵ�  
  {  
   if(root->lchild==NULL)//������Ϊ��ʱ  (��Ϊ����һ����Ϊ�գ��������Ҷ��)  
   {  
    p=root;                  // ��pָ��root  
    root=root->rchild;       // ��root���������ҵ�root��  
    delete(p);               // ɾ��p��ָ�ڵ�  
    shorter=true;            // ��ǰ�����߶ȼ�С  
   }  
   else //��������Ϊ��ʱ  
   {  
    p=f=root->lchild;         // ��p,fָ��root������  
    while(p->rchild)          // ��ת���ҵ���  
    {  
     f=p;                  //fΪp��ǰ��  
     p=p->rchild;          //p����������  
    }  
    if(p==f)                      //��ʱpû��������  
    {//��root�����������ڵ㲹�������µ�root,ɾ����ǰ��root  
     p=root;                   //��pָ��root  
     root=f;                   //��rootָ��f  
     root->rchild=p->rchild;   //��p���������ҵ���root��������  
     if(p->bf==0)//���ԭ������ƽ������  
     {  
      shorter=false;        //��ǰ���߶�û�м�С  
      root->bf=-1;          //���µ�ǰ������ƽ������  
     }  
     else if(p->bf==1)           
     {  
      shorter=true;         //��ǰ���߶ȼ�С  
      root->bf=0;           //����ƽ������  
     }  
     else  
     {  
      root->bf=p->bf-1;     //����ƽ������  
         RightBalance(root);   //��ʱ�൱�����������ӽڵ�  
      shorter=true;         //��ǰ���߶ȼ�С  
     }  
     delete p;                 //ɾ����ɾ�ڵ�  
    }  
    else  
    {// ��ʱ��ɾ���ڵ������������ұߵĽڵ��������ɾ�����ұߵĽڵ�  
     root->data=p->data;       //�������ڵ������  
     f->rchild=p->lchild;      //��p���������ҵ���ǰ��f����������  
     delete p;                 //ɾ��p��ָ�Ľ��  
     if(f->bf==0)              //���fƽ������  
     {  
      shorter=false;        //��ǰ��fΪ����������û�����仯  
      f->bf=1;              //����f��ƽ������  
     }  
     else if(f->bf==1)  
     {  
      LeftBalance(root->lchild);//��ǰ��fΪ��������������ƽ�⴦��(�൱��������ӽڵ�)  
      shorter=true;  
     }  
     else  
     {  
      shorter=true;           //��f Ϊ��������ƽ��δ���ƻ������߶ȼ�С  
      f->bf=0;                //����f��ƽ������  
     }  
     if(shorter)                 //����f Ϊ�����������߼�Сʱ,����ƽ�⴦��  
     {//�����������������  
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
       RightBalance(root);//�൱���ұ�����  
       shorter=true;  
      }  
     }  
    }  
   }  
  }  
 }  
 else if(data<root->data)        //��ɾ��������С�ڵ�ǰ��������  
 {  
  BBT_Del(root->lchild,data,shorter,suc,del,leaf);   //�ݹ飬����root���������м������ñ�����  
  if(del&&leaf)                       //ɾ������Ҷ�ӽڵ�  
  {  
   root->lchild=NULL;              //��ǰ����������ָ����Ϊ��  
   del=false;                      //���� del��ֵ  
  }  
  if(shorter)                        //shorterΪ�棬���߼�С������ƽ�����ӣ�����ƽ�⴦��  
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
 else//��ɾ�������ݴ��ڵ�ǰ��������  
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
 //����ƽ������  
int Find_BF(B_Point root,int data)              
{  
 if(!root)  
  return 100;//100��ʾ������,���ñ�ʾ����ʧ��  
 if(data==root->data)    
  return root->bf;                        //�ҵ������ݽڵ㣬����ƽ������  
 else if(data<root->data)                    //����ݹ����  
  return Find_BF(root->lchild,data);  
 else return Find_BF(root->rchild,data);  
}  
//�������  
void Traverse(B_Point root)  
{  
 if(root)//��ǰ���ڵ㲻Ϊ��  
 {  
  Traverse(root->lchild);           //���������еݹ�  
  printf("%d ",root->data);         //��ʾ��ǰ�ڵ�Ϊ����  
  Traverse(root->rchild);           //���������еݹ�  
 }  
}  
//��ȡ����  
void GetTreeHeight(B_Point root,int TreeHeight,int & MaxHeight)  
{  
 if(root)                                               //��ǰ���ڵ㲻Ϊ��  
 {  
  TreeHeight++;                                      //���߼�1  
  if(TreeHeight>MaxHeight) MaxHeight=TreeHeight;     //���������ֵ�Ƚ�  
  GetTreeHeight(root->lchild,TreeHeight,MaxHeight);  //���������еݹ�  
  GetTreeHeight(root->rchild,TreeHeight,MaxHeight);  //���������еݹ�  
 }  
}  