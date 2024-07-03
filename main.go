package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"fmt"
	"os/signal"
	"os/exec"
	"strings"
	"bufio"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type ssl_data_event_t bpf ssl.c

func findLibraryPath(libname string) (string, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ldconfig -p | grep %s", libname))

	// Run the command and get the output
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to run ldconfig: %w", err)
	}

	// Read the first line of output which should have the library path
	scanner := bufio.NewScanner(&out)
	if scanner.Scan() {
		line := scanner.Text()
		// Extract the path from the ldconfig output
		if start := strings.LastIndex(line, ">"); start != -1 {
			path := strings.TrimSpace(line[start+1:])
			return path, nil
		}
	}

	return "", fmt.Errorf("library not found")
}


func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	opensslPath, err := findLibraryPath("libssl.so");
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("OpenSSL path: %s\n", opensslPath);

	// Open an ELF binary and read its symbols.
	ex, err := link.OpenExecutable(opensslPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	// Set up SSL probes
	uprobe_ssl_write, err := ex.Uprobe("SSL_write", objs.UprobeLibsslWrite, nil)
	if err != nil {
		log.Fatalf("creating uprobe - SSL_write: %s", err)
	}
	defer uprobe_ssl_write.Close()

	uprobe_ssl_read, err := ex.Uprobe("SSL_read", objs.UprobeLibsslRead, nil)
	if err != nil {
		log.Fatalf("creating uprobe - SSL_read: %s", err)
	}
	defer uprobe_ssl_read.Close()

	uretprobe_ssl_read, err := ex.Uretprobe("SSL_read", objs.UretprobeLibsslRead, nil)
	if err != nil {
		log.Fatalf("Creating uretprobe - SSL_read: %s", err)
	}
	defer uretprobe_ssl_read.Close()

	rd, err := ringbuf.NewReader(objs.SslDataEventMap)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	var event bpfSslDataEventT
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfSslDataEventT structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing ringbuf event: %s", err)
			continue
		}

		msg_bytes := event.Buf[0:event.Len]
		msg := unix.ByteSliceToString(msg_bytes)

		msg_type := "Sent"
		if event.Egress == 0 {
			msg_type = "Received"
		}

		log.Printf("%s: pid: %d size: %d\n%s\n\n", msg_type, event.Pid, event.Len, msg)
	}
}
