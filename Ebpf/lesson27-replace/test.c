#include <stdlib.h>
#include <stdio.h>


int main(int argc, char ** argv) {
    printf("long unsigned int :"
            "signed int : "
            "size_t :\n", sizeof(long unsigned int), sizeof(unsigned int), sizeof(size_t));
    return 0;
}