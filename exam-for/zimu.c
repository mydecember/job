#include"stdio.h"
#include"string.h"
#define MAX_LINE_LEN 20
char dictionary[10][MAX_LINE_LEN]={{"and"},{"dick"},{"jane"},{"puff"},{"spot"},{"yertle"},{""}};

	char encry[1024]="bjvg xsb hxsn xsb qymm xsb rqat xsb pnetfn";
	char encry_sep[1000][MAX_LINE_LEN]={0};
	char encrymap[256]={0};
void encry_separate(char (*encry_dictionary),char (* encry_sep)[MAX_LINE_LEN],int num)
{
	int j=0,i=0,line=-1;
	char tmp[100];
	for(i=0;i<num;++i)
	{
	//	printf("%c",encry_dictionary[i]);
		if(encry_dictionary[i]!=' '&&i!=num-1)
		{
			//miwendui[line][j]=miwen[]
			tmp[j++]=encry_dictionary[i];
		}
		else
		{
			if(i==num-1)
			{
				tmp[j++]=encry_dictionary[i];
				//j++;
			}
			tmp[j]=0;
		//	puts(tmp);
			j=0;
			while(j<=line)
			{
				if(!strcmp(encry_sep[j++],tmp))
					break;
			}
			if(j>line)
			{
					line++;
				strcpy(encry_sep[line],tmp);
			
			
			}
			j=0;
			
		}
	}
	strcpy(encry_sep[++line],"");
//	puts("--------");
}
void show(int array[][MAX_LINE_LEN],int n)
{
	int i=0; 
	int j=1;
	int findnum=0;
	int len=0;
/*	for(i=0;i<n;++i)
	{
		len=strlen(k[i]);
		printf("%d\n",len);
		
			for(j=0;j<=array[len][0];++j)
			{
				printf("%d,",array[len][j]);
			}
			printf("\n");
	}
*/
//	int n=0;
	n=0;
	for(i=0;i<MAX_LINE_LEN;++i)
	{
		if(array[i][0]>0)
		{
			n=0;
			printf("line:%d,%d, ",i,array[i][0]);
			for(j=1;n<array[i][0];++j)
			{
				
				if(array[i][j]!=-1)
				{
					printf("%d,",array[i][j]);
					n++;
					
				}
			}
			printf("\n");

		}
	}
}
int isunique(int array[][MAX_LINE_LEN],int array1[][MAX_LINE_LEN],int line,int col, int index,int *diccol)
{
	int i,j;
	char tmp1;
	char tmp2;
	//printf("%d,line:%d, col:%d, index:%d\n",array[line][0],line,col,index);
	int t=array[line][col];
	if(array[line][0]==0)
	{//printf("%d,line:%d, col:%d, index:%d\n",array[line][0],line,col,index);
		return 0;
	}
	if(array[line][0]==1)
		printf("{{{{{{{{{{\n");

	tmp1=encry_sep[t][index];
//	printf("tmp1:%c\n",tmp1);
	if(encrymap[tmp1]==0)
	{
		//printf("rrrrr\n");
		return 0;
	}
	//printf("ccccccc\n");
	int count=0;
		i=1;
	int findnum=0;
	while(1)
	{
		if(array[line][i]>-1)
		{
			t=array[line][i];
			if(encry_sep[t][index]==tmp1)
				findnum++;
			count++;
			if(count==array[line][0])
				break;
		}
		i++;
	//	printf("%d,%d,%d\n",array[line][0],count,i);
	}
	if(findnum>1)
		return 0;
	tmp2=encrymap[tmp1];
	i=1;
	findnum=0;
	count=0;
	int dc=0;
	while(1)
	{
		if(array1[line][i]>-1)
		{
			t=array1[line][i];
			if(dictionary[t][index]==tmp2)
			{
				dc=i;
				findnum++;
			}
			count++;
			if(count==array1[line][0])
				break;
		}
		i++;
	}
	if(findnum>1)
		return 0;
	*diccol=dc;
	printf("%d,%d,%d\n",array1[line][0],dc,col);
	printf("%d,%d\n",array1[line][dc],array[line][col]);
//	array1[line][dc]=-1;
//	array1[line][0]--;
	return 1;

}
int main()
{
	
	encry_separate(encry,encry_sep,strlen(encry));//separat the encry
	int i=0 ;
	int tmp;
	int sepnum=0;
	int dicnum=0;
	int len_num_max;
	while(strcmp(encry_sep[i],""))
	{
		sepnum++;
		printf("%s\n",encry_sep[i]);
		i++;
	}
	i=0;
	while(strcmp(dictionary[i++],""))
	{
		dicnum++;
	//	printf("%s\n",encry_sep[i++]);
	}
printf("dicnum=%d,sepnum=%d\n",dicnum,sepnum);
	int dicindex[MAX_LINE_LEN][MAX_LINE_LEN]={0};
	int encryindex[MAX_LINE_LEN][MAX_LINE_LEN]={0};
	for(i=0;i<MAX_LINE_LEN;++i)
		for(tmp=0;tmp<MAX_LINE_LEN;++tmp)
		{
			if(tmp==0)
			{
				dicindex[i][tmp]=0;
				encryindex[i][tmp]=0;
			}
			else
			{
				dicindex[i][tmp]=-1;
				encryindex[i][tmp]=-1;
			}
		}

	for(i=0;i<dicnum;++i)
	{
	//	if(dicindex[strlen(dictionary[i])][0]==-1)
		//	dicindex[strlen(dictionary[i])][0]=1;
	//	else
			dicindex[strlen(dictionary[i])][0]++;
		tmp=dicindex[strlen(dictionary[i])][0];
		dicindex[strlen(dictionary[i])][tmp]=i;
	//	printf("%d\n",dicindex[strlen(dictionary[i])][0]);
	}
	for(i=0;i<sepnum;++i)
	{
	//	if(encryindex[strlen(encry_sep[i])][0]==-1)
	//		encryindex[strlen(encry_sep[i])][0]=1;
	//	else
			encryindex[strlen(encry_sep[i])][0]++;
		tmp=encryindex[strlen(encry_sep[i])][0];
		encryindex[strlen(encry_sep[i])][tmp]=i;
	}

	show(dicindex,dicnum);
	puts("");
	show(encryindex,sepnum);
puts("+++++++++++++++++++");

	//for(i=0;i<dicnum;++i)
	len_num_max=0;
	for(i=1;i<MAX_LINE_LEN;++i)
	{
		//if(dicindex[i][0]==1&&encryindex[i][0])
		if(dicindex[i][0]>len_num_max)
			len_num_max=dicindex[i][0];
	}
	
		int k;
						int keyencry;
						int keydic;
	for(i=1;i<=len_num_max;++i)
	{
		int len;
			for(len=1;len<MAX_LINE_LEN;++len)
			{

				if((dicindex[len][0]==i))
				{
					printf("mmmmm=%d\n",dicindex[len][0]);

					printf("len:%d\n",len);
					
					if(encryindex[len][0]==1)
					{
					 keyencry=encryindex[len][1];
					 keydic=dicindex[len][1];
						for(k=0;k<len;++k)
						{			
						//	if(encrymap[encry_sep[keyencry][k]]==0)
								encrymap[encry_sep[keyencry][k]]=dictionary[keydic][k];
						//	else
						//		printf("decode error\n");
						}
					encryindex[len][0]--;
						encryindex[len][1]=-1;
							dicindex[len][0]--;
						dicindex[len][1]=-1;
					/*			show(dicindex,dicnum);
						puts("");
						show(encryindex,sepnum);
						puts("+++++++++first++++++++++");*/

					}
					else
					{
					//	printf("nnn:%d\n",encryindex[len][0]);
					//	continue;
					//	int isunique(int array[][MAX_LINE_LEN],int array1[][MAX_LINE_LEN],int line,int col, int index,int *diccol)
						int index;
						int flag=1;
					
					//	for(index=0;index<)
						while(flag)
						{
							int col,p;
							flag=0;
							int t;
							int ii=1;
							int qq;
							int count=0;
								while(1)
								{
								//	printf("%d,%d,%d,%d\n",len,encryindex[len][0],count,ii);
									if(encryindex[len][ii]!=-1)
									{
										printf("encryindex[len][ii]=%d\n",encryindex[len][ii]);
										int index;
										for(index=0;index<len;++index)
										{
											if((dicindex[len][0]>0)&&isunique(encryindex,dicindex,len,ii,index,&qq))
											{
												flag=1;
											//	keyencry=ii;
											//	 keydic=qq;
												 keyencry=encryindex[len][ii];
												 keydic=dicindex[len][qq];
												// printf("%d->%d",keyencry,keydic);
												 printf("%s->%s\n",encry_sep[keyencry],dictionary[keydic]);
													for(k=0;k<len;++k)
													{			
														if(encrymap[encry_sep[keyencry][k]]==0)
															encrymap[encry_sep[keyencry][k]]=dictionary[keydic][k];
														else
															//printf("decode error\n");
														{
															if(encrymap[encry_sep[keyencry][k]]!=dictionary[keydic][k])
															{
																printf("match error\n");
																return -1;
															}

														}
													}
												//	printf("mmmmmmmmmmmm\n");
													encryindex[len][0]--;
													encryindex[len][ii]=-1;
												
													dicindex[len][0]--;
													dicindex[len][qq]=-1;
														printf("dicindex[len][0]=%d,%d,%d\n",dicindex[len][0],qq,ii);

													show(dicindex,dicnum);
											
													show(encryindex,sepnum);
														puts("-------____----");

											}
										}

										count++;
									//	printf("---%d,%d\n",encryindex[len][0],count);
										if(count==encryindex[len][0]||encryindex[len][0]<1)
											break;
									}
									ii++;
									if(ii==MAX_LINE_LEN)
										break;
								}
						}
					}
				}

			
			}

	}

	for(i=0;i<256;++i)
	{
		if(encrymap[i]!=0)
			printf("%c->%c\n",i,encrymap[i]);
	}
printf("mingwen:\n");
	for(i=0;i<strlen(encry);++i)
	{
		if(encry[i]!=' ')
		{
			printf("%c",encrymap[encry[i]]);
		}
		else
			printf("%c",' ');
	}
	printf("\n");
		show(dicindex,dicnum);
											
													show(encryindex,sepnum);
	return  1;
}