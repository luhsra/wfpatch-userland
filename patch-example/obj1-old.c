#include <stdio.h>
#include <unistd.h>

int test3(void);

int test1(int x, int y) {
    return x + y + test3();
}

static int static_func(int a) {
    printf("static(%d)", a);
    return a;
}

int test0(int base, int len) {
    for (int i = 0; i < len; i++) {
        int ret = test1(base, i);
        printf("> %d\n", static_func(ret));
    }
}


