
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>

/* msleep(): Sleep for the requested number of milliseconds, from https://stackoverflow.com/questions/1157209/is-there-an-alternative-sleep-function-in-c-to-milliseconds */
int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

void print_first_line(const char *filename) {
    FILE *file = fopen(filename, "r");  // open file for reading
    if (!file) {
        perror("Error opening file");
        return;
    }

    char buffer[1024];  // adjust size as needed
    if (fgets(buffer, sizeof(buffer), file) != NULL) {
        // fgets includes the newline if present, so we can print directly
        printf("First line: %s", buffer);
    } else {
        if (feof(file))
            printf("File is empty or contains no readable lines.\n");
        else
            perror("Error reading file");
    }

    fclose(file);
}


int main(int argc, const char** argv) {

  if (argc < 2) {
    printf("Usage: example1 FILE.txt\n");
    return 1;
  }
  else {
    const char* filename = argv[1];

    msleep(50);
    printf("Reading %s\n", filename);
    msleep(50);

    print_first_line(filename);

  }

  return 0;
}

