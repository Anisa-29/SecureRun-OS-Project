#include <stdio.h>
int main(void){ FILE*f=fopen("/etc/passwd","r"); puts(f?"ESCAPED":"BLOCKED"); return 0; }
