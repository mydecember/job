/*
Author: wangyao
Email: wangyao@cs.hit.edu.cn
*/
#include "acsmx.h"
#include "deltans.h"
/*
*  Text Data Buffer
*/ 
unsigned char text[MAXLEN];
extern int nline;

int main (int argc, char **argv) 
{
	int i, nocase = 0;
	FILE *fd;
	char filename[20];
	ACSM_STRUCT * acsm;

	if (argc < 3)
	{
		fprintf (stderr,"Usage: acsmx filename pattern1 pattern2 ...  -nocase\n");
		exit (0);
	}

	acsm = acsmNew ();

	strcpy (filename, argv[1]);
	fd = fopen(filename,"r");
	if(fd == NULL)
	{
		fprintf(stderr,"Open file error!\n");
		exit(1);
	}

	for (i = 1; i < argc; i++)
		if (strcmp (argv[i], "-nocase") == 0)
			nocase = 1;
	for (i = 2; i < argc; i++)
	{
		if (argv[i][0] == '-')
			continue;
		printf("%s,%d\n",argv[i],strlen (argv[i]));
		acsmAddPattern (acsm, argv[i], strlen (argv[i]), nocase,1);
	}
fgets(text,MAXLEN,fd);
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

	PrintSummary(acsm->acsmPatterns);
int a[10]={45,45,45,4,1};
#ifdef __HAVE__LOAD__
printf("-------%d\n", getSummary (acsm->acsmPatterns,a));
#endif

	acsmFree (acsm);

	printf ("\n### AC Match Finished ###\n");
//	system("pause");

	return (0);
}

