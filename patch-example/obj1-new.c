#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>

int test3(void);

int test4(int z) {
    return -1 * z;
}

int test1(int x, int y) {
    stderr = stdout;
    return x + y + test3() * test3() + test4(y);
}

static int static_var;

static int static_func(int a) {
    printf("static(%d)", a + static_var + 1);
    return a;
}

int test0(int base, int len) {
    void *mem = malloc(3);
    // Variable from Library
    errno += base;
    free(mem);
    
    fprintf(stderr, "foobar\n");
    fprintf(stderr, "stderr: foobar\n");
    
    for (int i = 0; i < len; i++) {
        int ret = test1(base, i);
        printf("> %d\n", static_func(ret));
    }

    fprintf(stderr, "stdout: foobar\n");
}
