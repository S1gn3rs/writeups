#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "../general.h"

void win() {
  printf("Congratulations, you win!!! You successfully changed the code flow\n");
  printf("Flag: %s\n", getflag());
}

int main() {
  init();
  int (*fp)();
  char buffer[64];

  fp = 0;

  printf("You win this game if you are able to call the function win.\n");

  gets(buffer);

  if(fp) {
      printf("Calling function pointer... jumping to %p\n", fp);
      fp();
  }
}
