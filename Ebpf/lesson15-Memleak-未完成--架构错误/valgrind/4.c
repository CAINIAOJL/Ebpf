#include <stdio.h>
#include <stdlib.h> 

/*
内存泄漏
*/

int main(void)
{
    char *p = malloc(1);
    *p = 'a'; 

    char c = *p; 

    printf("\n [%c]\n",c); 

    return 0;
}