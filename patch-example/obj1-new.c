#include <stdio.h>
#include <unistd.h>

int test3(void);

int test4(int z) {
    return -1 * z;
}

int test1(int x, int y) {
    return x + y + test3() * test3() + test4(y);
}


int test0(int base, int len) {
    for (int i = 0; i < len; i++) {
        int ret = test1(base, i);
        printf("> %d\n", ret);
    }
}
