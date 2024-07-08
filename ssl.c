//go:build ignore

#include "ssl.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Used to send SSL data to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16777216);
} ssl_data_event_map SEC(".maps");

// Used to pass data from the SSL_read_entry to exit
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ssl_read_data);
} ssl_read_data_map SEC(".maps");

SEC("uprobe/SSL_write")
int uprobe_libssl_write(struct pt_regs *ctx) {
    void* buf = (void *) PT_REGS_PARM2(ctx);
    u64 size =  PT_REGS_PARM3(ctx);

    u32 map_id = 0;
    // reserve/commit ring buffer API
    struct ssl_data_event_t* map_value = bpf_ringbuf_reserve(&ssl_data_event_map, sizeof(struct ssl_data_event_t), 0);
    if (!map_value) {
	    return 0; 
    }
    
    // Sanity check there's data in buffer 
    // otherwise discard the reserved memory in ring buffer
    if (size == 0) { 
        bpf_ringbuf_discard(map_value, 0);
        return 0;
    }

    // Store the PID and payload size
    map_value->pid = bpf_get_current_pid_tgid() >> 32;
    map_value->len = size;
    map_value->egress = 1;
	
    u32 buf_size = MAX_BUF_SIZE;
    if (size < buf_size) {
	    buf_size = size;
    }

    // Read data from the buffer
    if (bpf_probe_read_user(map_value->buf, buf_size, buf) != 0) {
        bpf_ringbuf_discard(map_value, 0);
        return 0;
    }

    // Based on the data in buffer, determine the type of HTTP Method
    u32 method = parse_http_method((char*)buf);
    if (method == -1) {
    	bpf_printk("Failed to parse HTTP method");
    }
    bpf_printk("HTTP Method ID: %d", method);

    // Submit the event to user space
    bpf_ringbuf_submit(map_value, 0);

    return 0;
}

SEC("uprobe/SSL_read")
int uprobe_libssl_read(struct pt_regs *ctx) {
    u32 zero = 0;
    struct ssl_read_data *data = bpf_map_lookup_elem(&ssl_read_data_map, &zero);
    if (!data) {
        return 0;
    }
	
    // Store buffer and size into map passed to the read/exit function 
    data->buf = PT_REGS_PARM2(ctx);
    data->len = PT_REGS_PARM3(ctx);

    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_libssl_read(struct pt_regs *ctx) {
    // Get the buffer and size from the read/entry
    u32 zero = 0;
    struct ssl_read_data *data = bpf_map_lookup_elem(&ssl_read_data_map, &zero);
    if (!data) {
        return 0;
    }	

    u32 map_id = 0;
    struct ssl_data_event_t* map_value = bpf_ringbuf_reserve(&ssl_data_event_map, sizeof(struct ssl_data_event_t), 0);
    if (!map_value) {
	    return 0; 
    }

    // Store the PID of the process that triggered this hook and 
    // indicate this is an incoming/ingress message
    map_value->pid = bpf_get_current_pid_tgid() >> 32;
    map_value->egress = 0;
	
    // Sanity check there's data in buffer 
    u64 size = PT_REGS_RC(ctx);
    if (size == 0) { 
        bpf_ringbuf_discard(map_value, 0);
        return 0;
    }
	
    u32 buf_size = MAX_BUF_SIZE;
    if (size < buf_size) {
	    buf_size = size;
    }
    map_value->len = buf_size;

    // Based on the data in buffer, determine the HTTP status
    u32 http_status = parse_http_status((char*)data->buf);
    if (http_status == -1) {
    	bpf_printk("Failed to parse HTTP status");
    }
    bpf_printk("HTTP STATUS CODE: %d", http_status);

    // "Transfer" data buffer from one map to another
    if (bpf_probe_read_user(map_value->buf, buf_size, (char*)data->buf) != 0) {
        bpf_ringbuf_discard(map_value, 0);
        return 0;
    }

    // Submit the event to the user space
    bpf_ringbuf_submit(map_value, 0);

    return 0;
}
