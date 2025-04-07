#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "wr_api.h"

/* gcc 1.c -I /home/czk/bianyi/WalRecord/src/interface -lwrapi -L /home/czk/bianyi/WalRecord/output/lib */

int main(void) {
    bool result = false;
    int fd = -1;
    int errorcode = 0;
    const char *errormsg = NULL;
    char *fileName = "wr_file_write";
    int ret = wr_file_write(0x20000001, "hello world", 10);
    if (ret != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }

    printf("%lld\n", ret);
    return 0;
}