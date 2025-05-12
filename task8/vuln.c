#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void secret() {
    printf("Access granted! Exploit successful.\n");
    system("/bin/sh");
}
void busted() {
    printf("You've been busted!\n");
}

void vulnerable() {
    char buffer[64];
    printf("Enter your name: ");
    gets(buffer);  // уязвимая функция
    printf("Hello, %s\n", buffer);
}

int main() {
    vulnerable();
    return 0;
}
