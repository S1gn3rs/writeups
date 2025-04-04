// compile
// gcc 3_return.c -o 3_return -fno-stack-protector -m32 -no-pie

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "../general.h"

char bss_buffer[64];

void win()
{
  printf("Congratulations, you win!!! You successfully changed the code flow\n");
  printf("%s\n", getflag());
}

int main()
{
  init();

  char stack_buffer[64] = {0};

  printf("You win this game if you are able to call the function win.'\n");

  gets(bss_buffer);

  gets(stack_buffer);
}
