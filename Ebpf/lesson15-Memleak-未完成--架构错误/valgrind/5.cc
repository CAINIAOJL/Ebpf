#include <stdio.h>
#include <stdlib.h>
#include <iostream> 

/*
不匹配地使用malloc/new/new[] 和 free/delete/delete[]
 */

int main(void)
{
    char *p = (char*)malloc(1);
    *p = 'a'; 

    char c = *p; 

    printf("\n [%c]\n",c);
    delete p;
    return 0;
}