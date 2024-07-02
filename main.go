package main

import (
	"os"
	"log"
	"fmt"
	"strings"
	"bufio"
	"bytes"
	"os/exec"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ssl ssl.c

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

func attachOpenssl(sslObjs sslObjects, path string) (error) {
	ex, err := link.OpenExecutable(path)
	if err != nil {
		log.Printf("error opening executable %s", path)
		return err
	}

	_, err = ex.Uprobe("SSL_write", sslObjs.ProbeSSL_writeExit, nil)
	if err != nil {
		log.Fatalf("error attaching %s uprobe", "SSL_write")
		return err
	}

	_, err = ex.Uretprobe("SSL_read", sslObjs.ProbeSSL_readExit, nil)
	if err != nil {
		log.Fatalf("error attaching %s uretprobe", "SSL_read")
		return err
	}

	return nil
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	sslObjs := sslObjects{}
	if err := loadSslObjects(&sslObjs, nil); err != nil {
		log.Fatal(err)
	}

	opensslPath, err := findLibraryPath("libssl.so");
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("OpenSSL path: %s\n", opensslPath);
	attachOpenssl(sslObjs, opensslPath);

	L7EventsReader, err := perf.NewReader(sslObjs.PerfSSL_events, int(4096)*os.Getpagesize())
	if err != nil {
		log.Fatal("error creating perf event array reader")
	}

	for {
		var record perf.Record
		err := L7EventsReader.ReadInto(&record)
		if err != nil {
			log.Print("error reading from perf array")
		}

		if record.LostSamples != 0 {
			log.Printf("lost samples l7-event %d", record.LostSamples)
		}

		if record.RawSample == nil || len(record.RawSample) == 0 {
			log.Print("read sample l7-event nil or empty")
			return
		}

		log.Println("read sample l7-event")
	}
}