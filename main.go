package main

import (
	"io"
	"os"
	"fmt"
	"log"
	"regexp"
	"strings"
	"unsafe"

	"golang.org/x/mod/semver"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ssl ssl.c

var libSSLRegex string = `.*libssl(?P<AdjacentVersion>\d)*-*.*\.so\.*(?P<SuffixVersion>[0-9\.]+)*.*`
var re *regexp.Regexp

type sslLib struct {
	path    string
	version string
}

func AttachSSlUprobes(pid uint32, executablePath string, version string, sslObjs sslObjects) error {
	ex, err := link.OpenExecutable(executablePath)
	if err != nil {
		log.Printf("error opening executable %s", executablePath)
		return err
	}

	if semver.Compare(version, "v3.0.0") >= 0 {
		log.Printf("attaching ssl uprobes v3")

		_, err = ex.Uprobe("SSL_write", sslObjs.SslWriteV3, nil)
		if err != nil {
			log.Fatalf("error attaching %s uprobe", "SSL_write")
			return err
		}

		_, err = ex.Uprobe("SSL_read", sslObjs.SslReadEnterV3, nil)
		if err != nil {
			log.Fatalf("error attaching %s uprobe", "SSL_read")
			return err
		}

		_, err = ex.Uretprobe("SSL_read", sslObjs.SslRetRead, nil)
		if err != nil {
			log.Fatalf("error attaching %s uretprobe", "SSL_read")
			return err
		}
	} else if semver.Compare(version, "v1.1.0") >= 0 { // accept 1.1 as >= 1.1.1 for now, linking to 1.1.1 compatible uprobes
		log.Fatalf("attaching ssl uprobes v1.1")

		_, err = ex.Uprobe("SSL_write", sslObjs.SslWriteV111, nil)
		if err != nil {
			log.Fatalf("error attaching %s uprobe", "SSL_write")
			return err
		}

		_, err = ex.Uprobe("SSL_read", sslObjs.SslReadEnterV111, nil)
		if err != nil {
			log.Fatalf("error attaching %s uprobe", "SSL_read")
			return err
		}

		_, err = ex.Uretprobe("SSL_read", sslObjs.SslRetRead, nil)
		if err != nil {
			log.Fatalf("error attaching %s uretprobe", "SSL_read")
			return err
		}
	} else if semver.Compare(version, "v1.0.2") >= 0 {
		log.Printf("attaching ssl uprobes v1.0.2")
		_, err = ex.Uprobe("SSL_write", sslObjs.SslWriteV102, nil)
		if err != nil {
			log.Fatalf("error attaching %s uprobe", "SSL_write")
			return err
		}

		_, err = ex.Uprobe("SSL_read", sslObjs.SslReadEnterV102, nil)
		if err != nil {
			log.Fatalf("error attaching %s uprobe", "SSL_read")
			return err
		}

		_, err = ex.Uretprobe("SSL_read", sslObjs.SslRetRead, nil)
		if err != nil {
			log.Fatalf("error attaching %s uretprobe", "SSL_read")
			return err
		}
	} else {
		return fmt.Errorf("unsupported ssl version: %s", version)
	}

	log.Printf("successfully attached ssl uprobes")
	return nil
}

func getPath(mappingLine string) string {
	mappingLine = strings.TrimSpace(mappingLine)
	elems := strings.Split(mappingLine, " ")

	// edge case
	// /usr/lib64/libssl.so.1.0.2k (deleted)

	path := elems[len(elems)-1]

	if strings.Contains(path, "(deleted)") {
		path = elems[len(elems)-2]
	}

	return path
}

func toString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func parseSSLlib(text string) (map[string]*sslLib, error) {
	res := make(map[string]*sslLib)
	matches := re.FindAllStringSubmatch(text, -1)

	if matches == nil {
		return nil, fmt.Errorf("no ssl lib found")
	}

	for _, groups := range matches {
		match := groups[0]

		paramsMap := make(map[string]string)
		for i, name := range re.SubexpNames() {
			if i > 0 && i <= len(groups) {
				paramsMap[name] = groups[i]
			}
		}

		// paramsMap
		// k : AdjacentVersion or SuffixVersion
		// v : 1.0.2 or 3 ...

		var version string
		if paramsMap["AdjacentVersion"] != "" {
			version = paramsMap["AdjacentVersion"]
		} else if paramsMap["SuffixVersion"] != "" {
			version = paramsMap["SuffixVersion"]
		} else {
			continue
		}

		// add "v." prefix
		if version != "" {
			version = "v" + version
		}

		path := getPath(match)
		res[path] = &sslLib{
			path:    path,
			version: version,
		}
	}

	return res, nil
}

func findSSLExecutablesByPid(procfs string, pid uint32) (map[string] *sslLib, error) {
	// look for memory mapping of the process
	file, err := os.Open(fmt.Sprintf("%s/%d/maps", procfs, pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	libsMap, err := parseSSLlib(toString(fileContent))
	if err != nil {
		return nil, err
	}

	for libPath, _ := range libsMap {
		fullpath := fmt.Sprintf("%s/%d/root%s", procfs, pid, libPath)

		// modify parsed path to match the full path
		if _, err := os.Stat(fullpath); os.IsNotExist(err) {
			delete(libsMap, libPath)
		} else {
			l := libsMap[libPath]
			l.path = fullpath
		}
	}

	// key : parsed path
	// value : full path and version
	return libsMap, nil
}

func AttachSslUprobesOnProcess(procfs string, pid uint32, sslObjs sslObjects) []error {
	errors := make([]error, 0)
	
	sslLibs, err := findSSLExecutablesByPid(procfs, pid)
	if err != nil {
		log.Println("error finding ssl lib")
		return errors
	}

	if len(sslLibs) == 0 {
		log.Println("no ssl lib found")
		return errors
	}

	for _, sslLib := range sslLibs {
		err = AttachSSlUprobes(pid, sslLib.path, sslLib.version, sslObjs)
		if err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}


func main() {

	re = regexp.MustCompile(libSSLRegex)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	sslObjs := sslObjects{}
	if err := loadSslObjects(&sslObjs, nil); err != nil {
		log.Fatal(err)
	}

	pid := uint32(os.Getpid())
	AttachSslUprobesOnProcess("/proc", pid, sslObjs)

	L7EventsReader, err := perf.NewReader(sslObjs.L7Events, int(4096)*os.Getpagesize())
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

		l7Event := (*bpfL7Event)(unsafe.Pointer(&record.RawSample[0]))

		protocol := L7ProtocolConversion(l7Event.Protocol).String()

		// copy payload slice
		payload := [1024]uint8{}
		copy(payload[:], l7Event.Payload[:])

		if (protocol == "HTTP") {
			log.Println("HTTP")
		} else if (protocol == "HTTP2") {
			log.Println("HTTP2")
		}
	}
}