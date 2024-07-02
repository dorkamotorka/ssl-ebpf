#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define MAX_PAYLOAD_SIZE 1024
#define PAYLOAD_PREFIX_SIZE 16

#define TLS_MASK 0x8000000000000000

#define PROTOCOL_UNKNOWN 0
#define PROTOCOL_HTTP	 1
#define PROTOCOL_HTTP2	 2

#define METHOD_UNKNOWN      0
#define METHOD_GET          1
#define METHOD_POST         2
#define METHOD_PUT          3
#define METHOD_PATCH        4
#define METHOD_DELETE       5
#define METHOD_HEAD         6
#define METHOD_CONNECT      7
#define METHOD_OPTIONS      8
#define METHOD_TRACE        9

#define MIN_METHOD_LEN      8
#define MIN_RESP_LEN        12

#define CLIENT_FRAME        1
#define SERVER_FRAME        2

#define MAGIC_MESSAGE_LEN 24

#if defined(__TARGET_ARCH_x86)
#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GOROUTINE(x) ((x)->r14)
#elif defined(__TARGET_ARCH_arm64) 
/* arm64 provides struct user_pt_regs instead of struct pt_regs to userspace */
#define GO_PARAM1(x) (((struct user_pt_regs *)(x))->regs[0])
#define GO_PARAM2(x) (((struct user_pt_regs *)(x))->regs[1])
#define GO_PARAM3(x) (((struct user_pt_regs *)(x))->regs[2])
#define GOROUTINE(x) (((struct user_pt_regs *)(x))->regs[28])
#endif

#define bpf_read_into_from(dst, src)                  \
({                                                    \
    if (bpf_probe_read(&dst, sizeof(dst), src) < 0) { \
        return 0;                                     \
    }                                                 \
})

struct go_interface {
    __s64 type;
    void* ptr;
};

struct go_read_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 read_start_ns;  
};

struct go_read_key {
    __u32 pid;
    __u64 goid; // goroutine id
    // __u64 fd; can't have fd at exit of read, because it is not available
};

struct go_req_key {
    __u32 pid;
    __u64 fd;
};

struct socket_key {
    __u64 fd;
    __u32 pid;
    __u8 is_tls;
};

struct read_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 read_start_ns;  
};

struct read_enter_args {
    __u64 id;
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 time;
};

struct trace_event_raw_sys_enter_write {
	struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    char * buf;
    __u64 count;
};

struct trace_event_raw_sys_enter_read {
    struct trace_entry ent;
    int __syscall_nr;
    unsigned long int fd;
    char * buf;
    __u64 count;
};

struct trace_event_raw_sys_exit_read {
    __u64 unused;
    __s32 id;
    __s64 ret;
};

struct l7_request {
    __u64 write_time_ns;  
    __u8 protocol;
    __u8 method;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 request_type;
    __u32 seq;
    __u32 tid;
};

struct l7_event {
    __u64 fd;
    __u64 write_time_ns;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 failed;
    __u8 is_tls;
    __u32 seq;
    __u32 tid;
};

struct padding {};
typedef long (*padding_fn)();


//OpenSSL_1_0_2
struct ssl_st_v1_0_2 {
    __s32 version;
    __s32 type;
    struct padding* method; //  const SSL_METHOD *method;
    // ifndef OPENSSL_NO_BIO
    struct bio_st_v1* rbio;  // used by SSL_read
    struct bio_st_v1* wbio;  // used by SSL_write
};

struct bio_st_v1_0_2 {
    struct padding* method; // BIO_METHOD *method;
    padding_fn callback; // long (*callback) (struct bio_st *, int, const char *, int, long, long);
    char* cb_arg; /* first argument for the callback */
    int init;
    int shutdown;
    int flags; /* extra storage */
    int retry_reason;
    int num; // fd
};


//OpenSSL_1_1_1
struct ssl_st_v1_1_1 {
    __s32 version;
    struct padding* method; //  const SSL_METHOD *method;
    struct bio_st_v1_1_1* rbio;  // used by SSL_read
    struct bio_st_v1_1_1* wbio;  // used by SSL_write
};

struct bio_st_v1_1_1 {
    struct padding* method; // const BIO_METHOD *method;
    padding_fn callback; // long (*callback) (struct bio_st *, int, const char *, int, long, long);
    padding_fn callback_ex;
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
};

//openssl-3.0.0
struct ssl_st_v3_0_0 {
    __s32 version;
    struct padding* method; // const SSL_METHOD *method;
    /* used by SSL_read */
    struct bio_st_v3_0_0* rbio;
     /* used by SSL_write */
    struct bio_st_v3_0_0* wbio;

};

struct bio_st_v3_0 {
    struct padding* libctx;  // OSSL_LIB_CTX *libctx;
    struct padding* method;  // const BIO_METHOD *method;
    padding_fn callback;     // BIO_callback_fn callback;
    padding_fn callback_ex;  // BIO_callback_fn_ex callback_ex;
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
};

static __always_inline
int parse_http_method(char *buf) {
    char buf_prefix[MIN_METHOD_LEN];
    long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(buf)) ;
    
    if (r < 0) {
        return 0;
    }

    if (buf_prefix[0] == 'G' && buf_prefix[1] == 'E' && buf_prefix[2] == 'T') {
            return METHOD_GET;
    }else if(buf_prefix[0] == 'P' && buf_prefix[1] == 'O' && buf_prefix[2] == 'S' && buf_prefix[3] == 'T'){
        return METHOD_POST;
    }else if(buf_prefix[0] == 'P' && buf_prefix[1] == 'U' && buf_prefix[2] == 'T'){
        return METHOD_PUT;
    }else if(buf_prefix[0] == 'P' && buf_prefix[1] == 'A' && buf_prefix[2] == 'T' && buf_prefix[3] == 'C' && buf_prefix[4] == 'H'){
        return METHOD_PATCH;
    }else if(buf_prefix[0] == 'D' && buf_prefix[1] == 'E' && buf_prefix[2] == 'L' && buf_prefix[3] == 'E' && buf_prefix[4] == 'T' && buf_prefix[5] == 'E'){
        return METHOD_DELETE;
    }else if(buf_prefix[0] == 'H' && buf_prefix[1] == 'E' && buf_prefix[2] == 'A' && buf_prefix[3] == 'D'){
        return METHOD_HEAD;
    }else if (buf_prefix[0] == 'C' && buf_prefix[1] == 'O' && buf_prefix[2] == 'N' && buf_prefix[3] == 'N' && buf_prefix[4] == 'E' && buf_prefix[5] == 'C' && buf_prefix[6] == 'T'){
        return METHOD_CONNECT;
    }else if(buf_prefix[0] == 'O' && buf_prefix[1] == 'P' && buf_prefix[2] == 'T' && buf_prefix[3] == 'I' && buf_prefix[4] == 'O' && buf_prefix[5] == 'N' && buf_prefix[6] == 'S'){
        return METHOD_OPTIONS;
    }else if(buf_prefix[0] == 'T' && buf_prefix[1] == 'R' && buf_prefix[2] == 'A' && buf_prefix[3] == 'C' && buf_prefix[4] == 'E'){
        return METHOD_TRACE;
    }
    return -1;
}

static __always_inline
int parse_http_status(char *buf) {

    char b[MIN_RESP_LEN];
    long r = bpf_probe_read(&b, sizeof(b), (void *)(buf)) ;
    
    if (r < 0) {
        return 0;
    }

    // HTTP/1.1 200 OK
    if (b[0] != 'H' || b[1] != 'T' || b[2] != 'T' || b[3] != 'P' || b[4] != '/') {
        return -1;
    }
    if (b[5] < '0' || b[5] > '9') {
        return -1;
    }
    if (b[6] != '.') {
        return -1;
    }
    if (b[7] < '0' || b[7] > '9') {
        return -1;
    }
    if (b[8] != ' ') {
        return -1;
    }
    if (b[9] < '0' || b[9] > '9' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9') {
        return -1;
    }
    return (b[9]-'0')*100 + (b[10]-'0')*10 + (b[11]-'0');
}

static __always_inline
int is_http2_magic(char *buf) {
    char buf_prefix[MAGIC_MESSAGE_LEN];
    long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(buf)) ;
    
    if (r < 0) {
        return 0;
    }

    const char packet_bytes[MAGIC_MESSAGE_LEN] = {
        0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
        0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
        0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a
    };

    for (int i = 0; i < MAGIC_MESSAGE_LEN; i++) {
        if (buf_prefix[i] != packet_bytes[i]) {
            return 0;
        }
    }

    return 1;
}

static __always_inline
int is_http2_magic_2(char *buf){
    char buf_prefix[MAGIC_MESSAGE_LEN];
    long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(buf)) ;

    if (r < 0) {
        return 0;
    }


    if (buf_prefix[0] == 'P' && buf_prefix[1] == 'R' && buf_prefix[2] == 'I' && buf_prefix[3] == ' ' && buf_prefix[4] == '*' && buf_prefix[5] == ' ' && buf_prefix[6] == 'H' && buf_prefix[7] == 'T' && buf_prefix[8] == 'T' && buf_prefix[9] == 'P' && buf_prefix[10] == '/' && buf_prefix[11] == '2' && buf_prefix[12] == '.' && buf_prefix[13] == '0'){
        return 1;
    }
    return 0;
}


static __always_inline    
int is_http2_frame(char *buf, __u64 size) {
    if (size < 9) {
        return 0;
    }

    // magic message is not a frame 
    if (is_http2_magic_2(buf)) {
        return 1;
    }
    
    // try to parse frame

    // 3 bytes length
    // 1 byte type
    // 1 byte flags
    // 4 bytes stream id
    // 9 bytes total

    // #length bytes payload

    __u32 length;
    bpf_read_into_from(length,buf);
    length = bpf_htonl(length) >> 8; // slide off the last 8 bits

    __u8 type;
    bpf_read_into_from(type,buf+3); // 3 bytes in
    
    // frame types are 1 byte
    // 0x00 DATA
    // 0x01 HEADERS
    // 0x02 PRIORITY
    // 0x03 RST_STREAM
    // 0x04 SETTINGS
    // 0x05 PUSH_PROMISE
    // 0x06 PING
    // 0x07 GOAWAY
    // 0x08 WINDOW_UPDATE
    // 0x09 CONTINUATION

    // other frames can precede headers frames, so only check if its a valid frame type
    if (type > 0x09){
        return 0;
    }

    __u32 stream_id; // 4 bytes
    bpf_read_into_from(stream_id,buf+5);
    stream_id = bpf_htonl(stream_id);

    // odd stream ids are client initiated
    // even stream ids are server initiated
    
    if (stream_id == 0) { // special stream for window updates, pings
        return 1;
    }
    
    // only track client initiated streams
    if (stream_id % 2 == 1) {
       return 1;
    }
    return 0;
}