#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "../general.h"

int very_complex_function(char* password) {
  char buffer[16];
  volatile int result;

  result = 0;
  strcpy(buffer, password);

  if(strcmp(buffer, getflag()) == 0)
    result = 1;

  return result;
}

int main() {
  init();

  char pass[64] = {0};
  read(0, pass, 63);

  if(very_complex_function(pass)){
      printf("Welcome back! Here is your secret token: %s\n", getflag());
  } else {
      printf("Unauthorized user/passwd\n");
  }
}
