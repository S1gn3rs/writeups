#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "../general.h"

int main() {
  init();
  int control;
  char buffer[64];

  printf("You win this game if you can change variable control\n");

  control = 0;
  gets(buffer);

  if(control != 0) {
      printf("YOU WIN!\n");
      printf("Take my secrets: %s\n", getflag());
  } else {
      printf("Try again...\n");
  }
}
