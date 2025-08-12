#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "gr_api.h"

/* gcc 1.c -I /home/czk/bianyi/WalRecord/src/interface -lgrapi -L /home/czk/bianyi/WalRecord/output/lib */

int errorcode = 0;
const char *errormsg = NULL;    

#define uint32_t unsigned int
#define int32_t int
#define uint8 unsigned char
#define uint16 unsigned short
#define bool32 unsigned int

#define _SS_MAXSIZE 128
#define _SS_ALIGNSIZE (8)

#define _SS_PAD1SIZE (_SS_ALIGNSIZE - sizeof (short))
#define _SS_PAD2SIZE (_SS_MAXSIZE - (sizeof (short) + _SS_PAD1SIZE + _SS_ALIGNSIZE))

//typedef int socklen_t;
typedef int socket_t;

#define uint64 unsigned long long
#define int64 long long 

typedef struct st_gr_packet_head {
    uint32_t version;
    uint32_t client_version;
    uint32_t size;
    uint8 cmd;    /* command in request packet */
    uint8 result; /* code in response packet, success(0) or error(1) */
    uint16 flags;
    uint32_t serial_number;
    uint8 reserve[60];
} gr_packet_head_t;

typedef struct st_gr_packet {
    uint32_t offset;   // for reading
    uint32_t options;  // options
    gr_packet_head_t *head;
    uint32_t max_buf_size;  // MAX_ALLOWED_PACKET
    uint32_t buf_size;
    char *buf;
    char init_buf[10240];
} gr_packet_t;

typedef enum en_cs_pipe_type {
    CS_TYPE_TCP = 1,
    CS_TYPE_IPC = 2,
    CS_TYPE_DOMAIN_SCOKET = 3,
    CS_TYPE_SSL = 4,
    CS_TYPE_EMBEDDED = 5, /* embedded mode, reserved */
    CS_TYPE_DIRECT = 6,   /* direct mode, reserved */
    CS_TYPE_RDMA = 7,     /* direct mode, reserved */
    CS_TYPE_CEIL
} cs_pipe_type_t;

struct sockaddr_storage {
    short ss_family;
    char __ss_pad1[_SS_PAD1SIZE];

    __extension__ long long __ss_align;
    char __ss_pad2[_SS_PAD2SIZE];
  };

typedef struct st_sock_addr {
    struct sockaddr_storage addr;
    socklen_t salen;
} sock_addr_t;

typedef struct st_tcp_link {
    socket_t sock; // need to be first!
    bool32 closed; // need to be second!
    sock_addr_t remote;
    sock_addr_t local;
} tcp_link_t;

typedef union un_cs_link {
    tcp_link_t tcp;
    //ssl_link_t ssl;
    //uds_link_t uds; // other links can be added later
} cs_link_t;

typedef struct st_cs_pipe {
    cs_pipe_type_t type;
    cs_link_t link;
    uint32_t options;
    uint32_t version;
    int32_t connect_timeout; // ms
    int32_t socket_timeout;  // ms
    int32_t l_onoff;
    int32_t l_linger;
} cs_pipe_t;

typedef struct gr_cli_info {
    uint64 cli_pid;
    int64 start_time;
    char process_name[256];
    uint32_t thread_id;
    uint64 connect_time;
} gr_cli_info_t;

typedef struct st_gr_conn {
    gr_packet_t pack;  // for sending
    cs_pipe_t pipe;
    void *cli_vg_handles;
    bool32 flag;
    void *session;
    uint32_t server_version;
    uint32_t proto_version;
#ifdef ENABLE_GRTEST
    pid_t conn_pid;
#endif
    gr_cli_info_t cli_info;
} gr_conn_t;

typedef struct st_gr_instance_handle {
    gr_conn_t *conn;
    char addr[64];
} st_gr_instance_handle;


// server_address
const char* serverAddr = "20.20.20.20:18440";
const char* remoteServerAddr = "20.20.20.11:18440";
const char* errorAddr = "111";

/* 
 * 测试：连接本节点grserver
 * 前提：本节点grserver未启动
 * 期望结果：连接失败
 */
void test_case_1()
{
    printf(" test case1: ***************\n");
    gr_instance_handle gr_init_handle = NULL;

    int result = gr_create_inst(serverAddr, &gr_init_handle);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case1: success  ***************\n");
        gr_delete_inst(gr_init_handle);
        return;
    }
    printf(" test case1: failed  ***************\n");
}

/* 
 * 测试：连接本节点grserver
 * 前提：本节点grserver启动
 * 期望结果：连接成功
 */
void test_case_2()
{
    printf(" test case2: ***************\n");
    gr_instance_handle gr_init_handle = NULL;

    int result = gr_create_inst(serverAddr, &gr_init_handle);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case2: failed  ***************\n");
        gr_delete_inst(gr_init_handle);
        return;
    }
    printf(" test case2: success  ***************\n");
    gr_delete_inst(gr_init_handle);
}

/* 
 * 测试：跨节点连接grserver
 * 前提：其他节点grserver未启动
 * 期望结果：连接失败
 */
void test_case_3()
{
    printf(" test case3: ***************\n");
    gr_instance_handle gr_init_handle = NULL;

    int result = gr_create_inst(serverAddr, &gr_init_handle);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case3: success  ***************\n");
        gr_delete_inst(gr_init_handle);
        return;
    }
    printf(" test case3: failed  ***************\n");
}

/* 
 * 测试：跨节点连接grserver
 * 前提：其他节点grserver启动
 * 期望结果：连接成功
 */
void test_case_4()
{
    printf(" test case4: ***************\n");
    gr_instance_handle gr_init_handle = NULL;

    int result = gr_create_inst(remoteServerAddr, &gr_init_handle);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case4: failed  ***************\n");
        gr_delete_inst(gr_init_handle);
        return;
    }
    printf(" test case4: success  ***************\n");
    gr_delete_inst(gr_init_handle);
}

/* 
 * 测试：传入的地址格式异常
 * 前提：无
 * 期望结果：连接失败
 */
void test_case_5()
{
    printf(" test case5: ***************\n");
    gr_instance_handle gr_init_handle = NULL;

    int result = gr_create_inst(errorAddr, &gr_init_handle);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case5: success  ***************\n");
        gr_delete_inst(gr_init_handle);
        return;
    }
    printf(" test case5: failed  ***************\n");
}

/* 
 * 测试：本节点创建多个连接
 * 前提：本节点grserver启动
 * 期望结果：连接成功
 */
void test_case_6()
{
    printf(" test case6: ***************\n");
    gr_instance_handle gr_init_handle1 = NULL;
    gr_instance_handle gr_init_handle2 = NULL;
    gr_instance_handle gr_init_handle3 = NULL;

    int result = gr_create_inst(serverAddr, &gr_init_handle1);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case6: failed  ***************\n");
        gr_delete_inst(gr_init_handle1);
        return;
    }

    gr_create_inst(serverAddr, &gr_init_handle2);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case6: failed  ***************\n");
        gr_delete_inst(gr_init_handle2);
        return;
    }

    gr_create_inst(serverAddr, &gr_init_handle3);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case6: failed  ***************\n");
        gr_delete_inst(gr_init_handle3);
        return;
    }

    printf(" test case6: success  ***************\n");
    gr_delete_inst(gr_init_handle1);
    gr_delete_inst(gr_init_handle2);
    gr_delete_inst(gr_init_handle3);
}

/* 
 * 测试：跨节点创建多个连接
 * 前提：其他节点grserver启动
 * 期望结果：连接成功
 */
void test_case_7()
{
    printf(" test case7: ***************\n");
    gr_instance_handle gr_init_handle1 = NULL;
    gr_instance_handle gr_init_handle2 = NULL;
    gr_instance_handle gr_init_handle3 = NULL;

    int result = gr_create_inst(remoteServerAddr, &gr_init_handle1);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case7: failed  ***************\n");
        gr_delete_inst(gr_init_handle1);
        return;
    }

    gr_create_inst(remoteServerAddr, &gr_init_handle2);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case7: failed  ***************\n");
        gr_delete_inst(gr_init_handle2);
        return;
    }

    gr_create_inst(remoteServerAddr, &gr_init_handle3);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case7: failed  ***************\n");
        gr_delete_inst(gr_init_handle3);
        return;
    }

    printf(" test case7: success  ***************\n");
    gr_delete_inst(gr_init_handle1);
    gr_delete_inst(gr_init_handle2);
    gr_delete_inst(gr_init_handle3);
}

/* 
 * 测试：连接本节点和跨节点连接
 * 前提：其他节点grserver启动
 * 期望结果：连接成功
 */
void test_case_8()
{
    printf(" test case8: ***************\n");
    gr_instance_handle gr_init_handle1 = NULL;
    gr_instance_handle gr_init_handle2 = NULL;
    gr_instance_handle gr_init_handle3 = NULL;
    gr_instance_handle gr_init_handle4 = NULL;

    int result = gr_create_inst(serverAddr, &gr_init_handle1);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case8: failed  ***************\n");
        gr_delete_inst(gr_init_handle1);
        return;
    }

    gr_create_inst(serverAddr, &gr_init_handle2);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case8: failed  ***************\n");
        gr_delete_inst(gr_init_handle2);
        return;
    }

    gr_create_inst(remoteServerAddr, &gr_init_handle3);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case8: failed  ***************\n");
        gr_delete_inst(gr_init_handle3);
        return;
    }

    gr_create_inst(remoteServerAddr, &gr_init_handle4);
    if (result != 0) {
        gr_get_error(&errorcode, &errormsg);
        printf("%d : %s\n", errorcode, errormsg);
        printf(" test case8: failed  ***************\n");
        gr_delete_inst(gr_init_handle4);
        return;
    }

    printf(" test case8: success  ***************\n");
    gr_delete_inst(gr_init_handle1);
    gr_delete_inst(gr_init_handle2);
    gr_delete_inst(gr_init_handle3);
    gr_delete_inst(gr_init_handle4);
}


int main(void) {
    test_case_1();
    test_case_2();
    test_case_3();
    test_case_4();
    test_case_5();
    test_case_6();
    test_case_7();
    test_case_8();
    return 0;
}