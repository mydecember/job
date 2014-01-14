#include"stdio.h"
int main()
{
	char fname[]="/home";
	printf("%d\n",ftok(fname ,0));
		printf("%d\n",ftok(fname ,1));
			printf("%d\n",ftok(fname ,2));
				printf("%d\n",ftok(fname ,3));
	return 1;
}