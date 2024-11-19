#include <stdio.h>
#include <stdlib.h> 

/*
在内存被释放后进行读/写
*/

int main(void)
{
    char *p = malloc(1);
    *p = 'a'; 

    char c = *p; 

    printf("\n [%c]\n",c); 

    free(p);
    c = *p;
    return 0;
}