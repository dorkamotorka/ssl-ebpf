//go:build ignore

#include "ssl.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Instead of allocating on bpf stack, we allocate on a per-CPU array map due to BPF stack limit of 512 bytes
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

// Instead of allocating on bpf stack, we allocate on a per-CPU array map due to BPF stack limit of 512 bytes
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

// To transfer read parameters from enter to exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct socket_key);
    __type(value, struct l7_request);
} active_l7_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct go_req_key);
    __type(value, struct l7_request);
} go_active_l7_requests SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} go_l7_request_heap SEC(".maps");

// Map to share l7 events with the userspace application
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct go_read_key);
    __uint(value_size, sizeof(struct go_read_args));
    __uint(max_entries, 10240);
} go_active_reads SEC(".maps");

// Processing enter of write syscall triggered on the client side
static __always_inline
int process_enter_of_syscalls_write(void* ctx, __u64 fd, __u8 is_tls, char* buf, __u64 payload_size) {
    // Retrieve the l7_request struct from the eBPF map (check above the map definition, why we use per-CPU array map for this purpose)
    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);
    if (!req) {
        return 0;
    }
    
    req->protocol = PROTOCOL_UNKNOWN;
    req->method = METHOD_UNKNOWN;
    req->request_type = 0;
    if (buf) {
        int method = parse_http_method(buf);
        if (method != -1) {
            req->protocol = PROTOCOL_HTTP;
            req-> method = method;
        } else if (is_http2_frame(buf, payload_size)) {
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }

            e->protocol = PROTOCOL_HTTP2;
            e->method = CLIENT_FRAME;
            e->is_tls = 1;
            bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, buf);
            if (payload_size > MAX_PAYLOAD_SIZE) {
                // will not be able to copy all of it
                e->payload_size = MAX_PAYLOAD_SIZE;
                e->payload_read_complete = 0;
            } else {
                e->payload_size = payload_size;
                e->payload_read_complete = 1;
            }
            

            long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            if (r < 0) {
                bpf_printk("failed write to l7_events -- res|fd|psize");       
            }
            return 0;
        }
    }

    // Copy the payload from the packet and check whether it fit below the MAX_PAYLOAD_SIZE
    bpf_probe_read(&req->payload, sizeof(req->payload), (const void *)buf);
    if (payload_size > MAX_PAYLOAD_SIZE) {
        // We werent able to copy all of it (setting payload_read_complete to 0)
        req->payload_size = MAX_PAYLOAD_SIZE;
        req->payload_read_complete = 0;
    } else {
        req->payload_size = payload_size;
        req->payload_read_complete = 1;
    }

    // Store active L7 request struct for later usage
    struct socket_key k = {};
    __u64 id = bpf_get_current_pid_tgid();
    k.pid = id >> 32;
    k.fd = fd;
    long res = bpf_map_update_elem(&active_l7_requests, &k, req, BPF_ANY);
    if (res < 0) {
        bpf_printk("Failed to store struct to active_l7_requests eBPF map");
    }

    return 0;
}

// Processing enter of read syscall triggered on the server side
static __always_inline
int process_enter_of_syscalls_read(void *ctx, struct read_enter_args *params) {
    __u64 id = bpf_get_current_pid_tgid();

    // Store an active read struct for later usage
    struct read_args args = {};
    args.fd = params->fd;
    args.buf = params->buf;
    args.size = params->size;
    long res = bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    if (res < 0) {
        bpf_printk("write to active_reads failed");     
    }

    return 0;
}

static __always_inline
int process_exit_of_syscalls_read_recvfrom(void* ctx, __u64 id, __u32 pid, __s64 ret, __u8 is_tls) {
    __u64 timestamp = bpf_ktime_get_ns();
    if (ret < 0) { // read failed
        struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &id);
        if (!read_info) {
            return 0;
        }

        struct socket_key k = {};
        k.pid = pid;
        k.fd = read_info->fd;
        k.is_tls = is_tls;

        // clean up
        bpf_map_delete_elem(&active_reads, &id);

        return 0;
    }

    struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &id);
    if (!read_info) {
        return 0;
    }
    
    struct socket_key k = {};
    k.pid = pid;
    k.fd = read_info->fd; 
    k.is_tls = is_tls;

    // Instead of allocating on bpf stack, use cpu map
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        bpf_map_delete_elem(&active_l7_requests, &k);
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
    e->is_tls = is_tls;

    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!active_req) {
        // if http2 server frame, send directly to userspace
        if (is_http2_frame(read_info->buf,ret)) {
            e->protocol = PROTOCOL_HTTP2;
            e->write_time_ns = timestamp;
            e->fd = read_info->fd;
            e->pid = k.pid;
            e->method = SERVER_FRAME;
            e->status = 0;
            e->failed = 0; // success
            e->duration = 0; // total write time
            e->is_tls = 1;
            bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, read_info->buf);
            if (ret > MAX_PAYLOAD_SIZE) {
                // will not be able to copy all of it
                e->payload_size = MAX_PAYLOAD_SIZE;
                e->payload_read_complete = 0;
            } else {
                e->payload_size = ret;
                e->payload_read_complete = 1;
            }

            long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            if (r < 0) {
                bpf_printk("failed write to l7_events h2 -- res|fd|psize");      
            }
            bpf_map_delete_elem(&active_reads, &id);
            return 0;
        }

        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    e->fd = k.fd;
    e->pid = k.pid;

    e->method = active_req->method;

    e->protocol = active_req->protocol;
    e->duration = timestamp - active_req->write_time_ns;
    
    e->write_time_ns = active_req->write_time_ns;
    
    // request payload
    e->payload_size = active_req->payload_size;
    e->payload_read_complete = active_req->payload_read_complete;
    
    // copy req payload
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

    e->failed = 0; // success

    // for distributed tracing
    e->seq = active_req->seq;
    e->tid = active_req->tid;

    e->status = 0;
    if (read_info->buf) {
        if(e->protocol == PROTOCOL_HTTP && ret > PAYLOAD_PREFIX_SIZE) { // if http, try to parse status code
            // read first 16 bytes of read buffer
            char buf_prefix[PAYLOAD_PREFIX_SIZE];
            long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(read_info->buf));
            
            if (r < 0) {
                bpf_map_delete_elem(&active_reads, &id);
                bpf_map_delete_elem(&active_l7_requests, &k); // TODO: check this line, should we delete the request here?
                return 0;
            }

            int status = parse_http_status(buf_prefix);
            if (status != -1) {
                e->status = status;
            } else {
                bpf_map_delete_elem(&active_reads, &id);
                return 0;
            }
        }
    } else {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
       
    bpf_map_delete_elem(&active_reads, &id);
    bpf_map_delete_elem(&active_l7_requests, &k);

    
    long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    if (r < 0) {
        bpf_printk("failed write to l7_events -- res|fd|psize");
    }

    return 0;
}

static __always_inline 
void ssl_uprobe_read_enter_v1_0_2(struct pt_regs *ctx, __u64 id,  __u32 pid, void* ssl, void* buffer, int num, size_t *count_ptr) {
    __u64 time = bpf_ktime_get_ns();
    struct ssl_st_v1_0_2 ssl_st;
    long r = bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    if(r < 0) {         
        bpf_printk("could not read ssl_st -- res||");
        return;                                                       
    };
    
    struct bio_st_v1_0_2 bio;                                                   
    r = bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.rbio);
    if (r < 0) {         
        bpf_printk("could not rbio -- res||");
        return;                                                       
    };                                                              
    __u32 fd = bio.num;

    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;
 
   
    struct read_enter_args params = {
        .id = id,
        .fd = fd,
        .buf = buf_ptr,
        .size = buf_size,
        .time = time
    };
    process_enter_of_syscalls_read(ctx, &params);            
}

static __always_inline 
void ssl_uprobe_write_v_1_1_1(struct pt_regs *ctx, void* ssl, void* buffer, int num, size_t *count_ptr) {
    struct ssl_st_v1_1_1 ssl_st;
    long r = bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    if(r < 0) {         
        bpf_printk("could not read ssl_st -- res||");
        return;                                                       
    };
    
    struct bio_st_v1_1_1 bio;                                                   
    r = bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.wbio);
    if (r < 0) {         
        bpf_printk("could not wbio -- res||");
        return;                                                       
    };                                                              
    __u32 fd = bio.num;
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;

    process_enter_of_syscalls_write(ctx, fd, 1, buf_ptr, buf_size);                   
}

static __always_inline 
void ssl_uprobe_read_enter_v1_1_1(struct pt_regs *ctx, __u64 id,  __u32 pid, void* ssl, void* buffer, int num, size_t *count_ptr) {
    __u64 time = bpf_ktime_get_ns();
    struct ssl_st_v1_1_1 ssl_st;
    long r = bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    if(r < 0) {         
        bpf_printk("could not read ssl_st -- res||");
        return;                                                       
    };
    
    struct bio_st_v1_1_1 bio;                                                   
    r = bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.rbio);
    if (r < 0) {         
        bpf_printk("could not rbio -- res||");
        return;                                                       
    };                                                              
    __u32 fd = bio.num;
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;
 
    struct read_enter_args params = {
        .id = id,
        .fd = fd,
        .buf = buf_ptr,
        .size = buf_size,
        .time = time
    };
    process_enter_of_syscalls_read(ctx, &params);            
}


static __always_inline 
void ssl_uprobe_write_v_3(struct pt_regs *ctx, void* ssl, void* buffer, int num, size_t *count_ptr) {
    struct ssl_st_v3_0_0 ssl_st;
    long r = bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    if(r < 0) {         
        bpf_printk("could not read ssl_st -- res||");
        return;                                                       
    };
    
    struct bio_st_v3_0 bio;                                                   
    r = bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.wbio);
    if (r < 0) {         
        bpf_printk("could not wbio -- res||");
        return;                                                       
    };                                                              
    __u32 fd = bio.num;
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;

    process_enter_of_syscalls_write(ctx, fd, 1, buf_ptr, buf_size);                   
}

static __always_inline 
void ssl_uprobe_read_enter_v3(struct pt_regs *ctx, __u64 id,  __u32 pid, void* ssl, void* buffer, int num, size_t *count_ptr) {
    __u64 time = bpf_ktime_get_ns();
    struct ssl_st_v3_0_0 ssl_st;
    long r = bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    if (r < 0) {         
        bpf_printk("could not read ssl_st -- res||");
        return;                                                       
    };
    
    struct bio_st_v3_0 bio;                                                   
    r = bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.rbio);
    if (r < 0) {         
        bpf_printk("could not rbio -- res||");
        return;                                                       
    };                                                              
    
    __u32 fd = bio.num;
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;
 
    struct read_enter_args params = {
        .id = id,
        .fd = fd,
        .buf = buf_ptr,
        .size = buf_size,
        .time = time

    };
    process_enter_of_syscalls_read(ctx, &params);            
}

static __always_inline
int process_enter_of_go_conn_write(void *ctx, __u32 pid, __u32 fd, char *buf_ptr, __u64 count) {
    __u64 timestamp = bpf_ktime_get_ns();
    struct go_req_key k = {};
    k.pid = pid;
    k.fd = fd;

    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&go_l7_request_heap, &zero);
    if (!req) {
        return 0;
    }
    req->method = METHOD_UNKNOWN;
    req->protocol = PROTOCOL_UNKNOWN;
    req->payload_size = 0;
    req->payload_read_complete = 0;
    req->write_time_ns = timestamp;
    req->request_type = 0;
   
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    req->tid = tid;

    if(buf_ptr){
        // try to parse only http1.1 for gotls reqs for now.
        int method = parse_http_method(buf_ptr);
        if (method != -1){
            req->protocol = PROTOCOL_HTTP;
            req-> method = method;
        }else if(is_http2_frame(buf_ptr, count)){
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }

            e->protocol = PROTOCOL_HTTP2;
            e->write_time_ns = timestamp;
            e->fd = k.fd;
            e->pid = k.pid;
            e->method = CLIENT_FRAME;
            e->status = 0;
            e->failed = 0; // success
            e->duration = 0; // total write time
            e->is_tls = 1;
            bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, buf_ptr);
            if(count > MAX_PAYLOAD_SIZE){
                // will not be able to copy all of it
                e->payload_size = MAX_PAYLOAD_SIZE;
                e->payload_read_complete = 0;
            }else{
                e->payload_size = count;
                e->payload_read_complete = 1;
            }
            
            long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
            if (r < 0) {
                bpf_printk("failed write to l7_events -- res|fd|psize");        
            }
            return 0;
        }else{
            req->protocol = PROTOCOL_UNKNOWN;
            req->method = METHOD_UNKNOWN;
            return 0; 
        }
    }

    // copy req payload
    bpf_probe_read(&req->payload, MAX_PAYLOAD_SIZE, buf_ptr);
    if (count > MAX_PAYLOAD_SIZE) {
        // will not be able to copy all of it
        req->payload_size = MAX_PAYLOAD_SIZE;
        req->payload_read_complete = 0;
    } else {
        req->payload_size = count;
        req->payload_read_complete = 1;
    }

    long res = bpf_map_update_elem(&go_active_l7_requests, &k, req, BPF_ANY);
    if(res < 0) {
        bpf_printk("write failed to go_active_l7_requests -- res|fd|method");
    }

    return 0;
}

static __always_inline 
void ssl_uprobe_write_v_1_0_2(struct pt_regs *ctx, void* ssl, void* buffer, int num, size_t *count_ptr) {
    struct ssl_st_v1_0_2 ssl_st;
    long r = bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    if(r < 0) {         
        bpf_printk("could not read ssl_st -- res||");
        return;                                                       
    };

    struct bio_st_v1_0_2 bio;                     
    r = bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.wbio);                              
    if(r < 0) {         
        bpf_printk("could not bio -- res||");
        return;                                                       
    };                                                              
    __u32 fd = bio.num;
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;

    process_enter_of_syscalls_write((struct pt_regs *)ctx, fd, 1, buf_ptr, buf_size);                   
}

SEC("uretprobe/SSL_read")
void ssl_ret_read(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | TLS_MASK;

    int returnValue = PT_REGS_RC(ctx);

    process_exit_of_syscalls_read_recvfrom(ctx, id, pid, returnValue, 1);
}

SEC("uprobe/SSL_write_v1_0_2")
void BPF_PROG(ssl_write_v1_0_2, void *ssl, void *buffer, int num) {
	ssl_uprobe_write_v_1_0_2((struct pt_regs *)ctx, ssl, buffer, num, 0);
}

SEC("uprobe/SSL_read_v1_0_2")
void BPF_PROG(ssl_read_enter_v1_0_2, void *ssl, void *buffer, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | TLS_MASK;
    ssl_uprobe_read_enter_v1_0_2((struct pt_regs *)ctx, id, pid, ssl, buffer, num, 0);
}

SEC("uprobe/SSL_write_v1_1_1")
void BPF_PROG(ssl_write_v1_1_1, void *ssl, void *buffer, int num) {
	ssl_uprobe_write_v_1_1_1((struct pt_regs *)ctx, ssl, buffer, num, 0);
}

SEC("uprobe/SSL_read_v1_1_1")
void BPF_PROG(ssl_read_enter_v1_1_1, void *ssl, void *buffer, int num) {  
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | TLS_MASK;
    ssl_uprobe_read_enter_v1_1_1((struct pt_regs *)ctx, id, pid, ssl, buffer, num, 0);
}

SEC("uprobe/SSL_write_v3")
void BPF_PROG(ssl_write_v3, void *ssl, void *buffer, int num) {
	ssl_uprobe_write_v_3((struct pt_regs *)ctx, ssl, buffer, num, 0);
}

SEC("uprobe/SSL_read_v3")
void BPF_PROG(ssl_read_enter_v3, void *ssl, void *buffer, int num) {     
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | TLS_MASK;
    ssl_uprobe_read_enter_v3((struct pt_regs *)ctx, id, pid, ssl, buffer, num, 0);
}

// (c *Conn) Write(b []byte) (int, error)
SEC("uprobe/go_tls_conn_write_enter")
int go_tls_conn_write_enter(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    __u32 fd;
    struct go_interface conn;
    // Registers contain the function arguments
    
    // X0(arm64) register contains the pointer to the first function argument, c *Conn
    if (bpf_probe_read_user(&conn, sizeof(conn), (void*)GO_PARAM1(ctx)) < 0) {
        return 0;
    };
    void* fd_ptr;
    if (bpf_probe_read_user(&fd_ptr, sizeof(fd_ptr), conn.ptr) < 0) {
        return 0;
    }
    
    if(!fd_ptr) {
        return 0;
    }
    if (bpf_probe_read_user(&fd, sizeof(fd), fd_ptr + 0x10) < 0) {
        return 1;
    }

    // X1(arm64) register contains the byte ptr, pointing to first byte of the slice
    char *buf_ptr = (char*)GO_PARAM2(ctx);
    // X2(arm64) register contains the length of the slice
    __u64 buf_size = GO_PARAM3(ctx);

    return process_enter_of_go_conn_write(ctx, pid, fd, buf_ptr, buf_size);
}

// func (c *Conn) Read(b []byte) (int, error)
SEC("uprobe/go_tls_conn_read_enter")
int go_tls_conn_read_enter(struct pt_regs *ctx) {
    __u64 timestamp = bpf_ktime_get_ns();
    __u32 fd;
    struct go_interface conn;


    // X0(arm64) register contains the pointer to the first function argument, c *Conn
    if (bpf_probe_read_user(&conn, sizeof(conn), (void*)GO_PARAM1(ctx))) {
        return 1;
    };
    void* fd_ptr;
    if (bpf_probe_read_user(&fd_ptr, sizeof(fd_ptr), conn.ptr)) {
        return 1;
    }
    if (bpf_probe_read_user(&fd, sizeof(fd), fd_ptr + 0x10)) {
        return 1;
    }

    // X1(arm64) register contains the byte ptr, pointing to first byte of the slice
    char *buf_ptr = (char*)GO_PARAM2(ctx);
    // // X2(arm64) register contains the length of the slice
    __u64 buf_size = GO_PARAM3(ctx);

    struct go_read_args args = {};
    args.fd = fd;
    args.buf = buf_ptr;
    args.size = buf_size;
    args.read_start_ns = timestamp;

    struct go_read_key k = {};
    k.goid = GOROUTINE(ctx);
    k.pid = bpf_get_current_pid_tgid() >> 32;

    long res = bpf_map_update_elem(&go_active_reads, &k, &args, BPF_ANY);
    if(res < 0) {
        bpf_printk("write failed to go_active_reads -- res|goid|");
    }
    return 0;
}

// attached to all RET instructions since uretprobe crashes go applications
SEC("uprobe/go_tls_conn_read_exit")
int go_tls_conn_read_exit(struct pt_regs *ctx) {
    __u64 timestamp = bpf_ktime_get_ns();
    // can't access to register we've access on read_enter here,
    // registers are changed.
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    long int ret = GO_PARAM1(ctx);

    struct go_read_key k = {};
    k.goid = GOROUTINE(ctx);
    k.pid = bpf_get_current_pid_tgid() >> 32;

    struct go_read_args *read_args = bpf_map_lookup_elem(&go_active_reads, &k);
    if (!read_args) {
        return 0;
    }
    if (ret < 0) {
        bpf_map_delete_elem(&go_active_reads, &k);
        return 0;
    }

    // if http2, send directly to userspace
    if (is_http2_frame(read_args->buf, ret)) {
        int zero = 0;
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }

        e->protocol = PROTOCOL_HTTP2;
        e->write_time_ns = timestamp;
        e->fd = read_args->fd;
        e->pid = k.pid;
        e->method = SERVER_FRAME;
        e->status = 0;
        e->failed = 0; // success
        e->duration = 0; // total write time
        e->is_tls = 1;
        bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, read_args->buf);
        if (ret > MAX_PAYLOAD_SIZE) {
            // will not be able to copy all of it
            e->payload_size = MAX_PAYLOAD_SIZE;
            e->payload_read_complete = 0;
        } else {
            e->payload_size = ret;
            e->payload_read_complete = 1;
        }

        long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        if (r < 0) {
            bpf_printk("failed write to l7_events -- res|fd|psize");       
        }
        bpf_map_delete_elem(&go_active_reads, &k);
        return 0;
    }

    struct go_req_key req_k = {};
    req_k.pid = k.pid;
    req_k.fd = read_args->fd;

    struct l7_request *req = bpf_map_lookup_elem(&go_active_l7_requests, &req_k);
    if (!req) {
        return 0;
    }

    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        bpf_map_delete_elem(&go_active_reads, &k);
        return 0;
    }

    e->duration = timestamp - req->write_time_ns;
    e->write_time_ns = req->write_time_ns;
    e->failed = 0; // success
    
    e->fd = read_args->fd;
    e->pid = k.pid;
    e->is_tls = 1;
    e->method = req->method;
    e->protocol = req->protocol;
    
    // request payload
    e->payload_size = req->payload_size;
    e->payload_read_complete = req->payload_read_complete;
    
    // copy req payload
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, req->payload);
    
    e->failed = 0; // success
    e->status = 0;
    // parse response payload
    if (read_args->buf && ret >= PAYLOAD_PREFIX_SIZE) {
        if (e->protocol == PROTOCOL_HTTP) { // if http, try to parse status code
            // read first 16 bytes of read buffer
            char buf_prefix[PAYLOAD_PREFIX_SIZE];
            long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(read_args->buf)) ;
            
            if (r < 0) {
                bpf_printk("read failed for resp buf -- res|goid|method");

                bpf_map_delete_elem(&go_active_reads, &k);
                // bpf_map_delete_elem(&go_active_l7_requests, &req_k); // TODO: check ?
                return 0;
            }

            int status = parse_http_status(buf_prefix);
            if (status != -1) {
                e->status = status;
            } else {
                // In case of write happens but read_exit probe doesn't get called for a request (sigkill of process?)
                // a read from the same socket (same pid-fd pair) after some time, can match with the previous write
                // if the latter is http1.1, requests can mismatch (if expression above will satisfy)
                // or(not http1.1) the status code will be 0 if continued processing.
                // So we'll clean up the request here if it's not a protocol we support before hand.
                // mismatches can still occur, but it's better than nothing.
                // TODO: find a solution for the mismatch problem

                bpf_map_delete_elem(&go_active_reads, &k);
                bpf_map_delete_elem(&go_active_l7_requests, &req_k);
                return 0;
            }
        } else {
            bpf_map_delete_elem(&go_active_reads, &k);
            return 0;
        }
    } else {
        bpf_map_delete_elem(&go_active_reads, &k);
        return 0;
    }

    bpf_map_delete_elem(&go_active_reads, &k);
    bpf_map_delete_elem(&go_active_l7_requests, &req_k);

    long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    if (r < 0) {
        bpf_printk("write failed to l7_events -- r|fd|method");
    }

    return 0;
}