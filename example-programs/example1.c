
#include "stdio.h"

int main(int argc, char** argv) {

  if (argc < 2) {
    printf("Usage: example1 FILE.txt\n");
    return 1;
  }
  else {
    char* filename = argv[1];

    printf("Reading %s\n", filename);
    // TODO

  }

  return 0;
}

