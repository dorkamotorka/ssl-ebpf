//go:build ignore

#include "ssl.h"

char __license[] SEC("license") = "Dual MIT/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ssl_data_event_map SEC(".maps");

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
    struct ssl_data_event_t* map_value = bpf_ringbuf_reserve(&ssl_data_event_map, sizeof(struct ssl_data_event_t), 0);
    if (!map_value) {
	return 0; 
    }
    
    // Sanity check there's data in buffer 
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

    // Read buffer
    if (bpf_probe_read_user(map_value->buf, buf_size, buf) != 0) {
	bpf_ringbuf_discard(map_value, 0);
	return 0;
    }

    u32 method = parse_http_method((char*)buf);
    if (method == -1) {
    	bpf_printk("Failed to parse HTTP method");
    }

    bpf_printk("HTTP Method ID: %d", method);
    //bpf_printk("%s", map_value->buf);

    bpf_ringbuf_submit(map_value, 0);

    return 0;
}

// For the libssl_read call, we need a uprobe to capture
// the user-provided buffer that the decoded result will 
// be read into.
SEC("uprobe/SSL_read")
int uprobe_libssl_read(struct pt_regs *ctx) {
    // Get a map element we can store the user's data pointer in
    u32 zero = 0;
    struct ssl_read_data *data = bpf_map_lookup_elem(&ssl_read_data_map, &zero);
    if (!data) {
        return 0;
    }
	
    // Store the address and size of the user-supplied buffer
    // that we will read the decrypted data back out of.
    data->buf = PT_REGS_PARM2(ctx);
    data->len = PT_REGS_PARM3(ctx);

    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_libssl_read(struct pt_regs *ctx) {
    // Once we libssl_read is complete, we can grab the buffer
    // again, and read the decrypted results back out of it.
    u32 zero = 0;
    struct ssl_read_data *data = bpf_map_lookup_elem(&ssl_read_data_map, &zero);
    if (!data) {
        return 0;
    }	

    // We can read out the arguments passed to SSL_read by the user's code
    // by pulling the value stashed in our uprobe (above).
    u32 map_id = 0;
    struct ssl_data_event_t* map_value = bpf_ringbuf_reserve(&ssl_data_event_map, sizeof(struct ssl_data_event_t), 0);
    if (!map_value) {
	return 0; 
    }

    // Store the PID and indicate this is an incoming message
    map_value->pid = bpf_get_current_pid_tgid() >> 32;
    map_value->egress = 0;
	
    // Return code of SSL_read is the number of bytes decrypted
    // If we got none, we can bail out.
    u64 size = PT_REGS_RC(ctx);
    if (size == 0) { 
	bpf_ringbuf_discard(map_value, 0);
	return 0;
    }
	
    // How much do we need to copy?
    u32 buf_size = MAX_BUF_SIZE;
    if (size < buf_size) {
	buf_size = size;
    }

    // Write the buffer size back so userspace can find it
    map_value->len = buf_size;

    u32 http_status = parse_http_status((char*)data->buf);
    if (http_status == -1) {
    	bpf_printk("Failed to parse HTTP status");
    }
    bpf_printk("HTTP STATUS CODE: %d", http_status);

    // Read it, and give up if it doesn't work
    if (bpf_probe_read_user(map_value->buf, buf_size, (char*)data->buf) != 0) {
	bpf_ringbuf_discard(map_value, 0);
	return 0;
    }

    bpf_ringbuf_submit(map_value, 0);

    return 0;
}
