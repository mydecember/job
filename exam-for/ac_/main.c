/*
Author: wangyao
Email: wangyao@cs.hit.edu.cn
*/
#include "acsmx.h"
#include "deltans.h"
/*
*  Text Data Buffer
*/ 
unsigned char text[MAXLEN]="wetwe http sdfsd";
//extern int nline;

static char pro_patern[120][256]={
{"http"},{"put"},{"get"}
};  

int main (int argc, char **argv) 
{
	int i, nocase = 0;
	
	char filename[20];
	ACSM_STRUCT * acsm;	

	acsm = acsmNew ();	

	//nocase = 0;
	for(i=0;i<3;++i)
	acsmAddPattern (acsm, pro_patern[i], strlen (pro_patern[i]), nocase,1);


	/* Generate GtoTo Table and Fail Table */
	acsmCompile (acsm);
printf("--------------------------------\n");
	NS_TIME(time);
NS_TIME_START(time);
	/*Search Pattern*/
	//while ( fgets(text,MAXLEN,fd) )
	//{
		acsmSearch (acsm, text, strlen (text), PrintMatch);
	//	nline++;
	//}
NS_TIME_END(time);

	//PrintSummary(acsm->acsmPatterns);
	ACSM_PATTERN * mlist = acsm->acsmPatterns;
	printf("\n### Summary ###\n");
	for (;mlist!=NULL;mlist=mlist->next)
	{
		if(mlist->nocase)
			printf("%12s : %5d\n",mlist->patrn,mlist->nmatch);
		else
			printf("%12s : %5d\n",mlist->casepatrn,mlist->nmatch);
mlist->nmatch=0;
	}
mlist = acsm->acsmPatterns;

for (;mlist!=NULL;mlist=mlist->next)
	{
		if(mlist->nocase)
			printf("%12s : %5d\n",mlist->patrn,mlist->nmatch);
		else
			printf("%12s : %5d\n",mlist->casepatrn,mlist->nmatch);
mlist->nmatch=0;
	}

	acsmFree (acsm);

	printf ("\n### AC Match Finished ###\n");
//	system("pause");

	return (0);
}

