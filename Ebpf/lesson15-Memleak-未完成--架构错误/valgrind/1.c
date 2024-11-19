#include <stdio.h>
#include <stdlib.h> 
/*
使用未初始化的内存
*/

int main(void)
{
    char *p; 

    char c = *p; 

    printf("\n [%c]\n",c); 

    return 0;
}