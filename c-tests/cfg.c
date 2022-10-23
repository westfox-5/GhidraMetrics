#include<stdio.h>

int foo() {
   return 9;
}

int main() {
    int a = 4;
    int b = a+5;
    int z = foo();
    if (a+b-a==z) {
	    printf("%s\n", "OK");
    } else {
	    printf("%s\n", "NO");
    }
    return 0;
}
