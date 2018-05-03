#include <stdio.h>
#include <string.h>

int main(int argc, char ** argv)
{
    char buf[80];
    printf("%p\n", buf); // address of the buf array
    puts("Enter name:");
    gets(buf);
    printf("%s\n", buf);
    return 0;
}
