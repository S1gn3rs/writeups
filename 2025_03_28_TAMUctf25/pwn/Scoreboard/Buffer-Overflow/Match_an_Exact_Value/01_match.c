#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "../general.h"

int main() {
  init();
  int control;
  char buffer[64];

  printf("You win this game if you can change variable control to the value 0x61626364\n");

  control = 0;
  gets(buffer);

  if (control == 0x61626364) {
      printf("Congratulations, you win!!! You correctly got the variable to the right value\n");
      printf("Flag: %s\n", getflag());
  } else {
      printf("Try again, you got 0x%08x\n, instead of 0x61626364", control);
  }
}
