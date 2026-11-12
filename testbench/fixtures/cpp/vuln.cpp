#include <cstdio>
#include <cstring>
#include <cstdlib>
void run(char* user) {
  char buf[32];
  strcpy(buf, user);
  system(user);
}
