#include <stdio.h>
#include <stdlib.h> 

/*
从已分配内存块的尾部进行读/写
*/

int main(void)
{
    char *p = malloc(1);
    *p = 'a'; 

    char c = *(p+1); 

    printf("\n [%c]\n",c); 

    free(p);
    return 0;
}