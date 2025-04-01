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
    char *fileName = "+data/test";
    char *targetName = "+data/name";
    ret = wr_fcreate(fileName, 0777)
    if (ret != 0) {
        wr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
    }

    printf("%lld\n", ret);
    return 0;
}