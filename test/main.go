package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

var (
	CertFilePath = "server.crt"
	KeyFilePath  = "server.key"
)

func httpRequestHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		w.Write([]byte("GET request received\n"))
	case http.MethodPost:
		w.Write([]byte("POST request received\n"))
	case http.MethodPut:
		w.Write([]byte("PUT request received\n"))
	case http.MethodPatch:
		w.Write([]byte("PATCH request received\n"))
	case http.MethodDelete:
		w.Write([]byte("DELETE request received\n"))
	case http.MethodHead:
		w.Header().Set("Content-Type", "text/plain")
	case http.MethodConnect:
		w.Write([]byte("CONNECT request received\n"))
	case http.MethodOptions:
		w.Header().Set("Allow", "GET, POST, PUT, PATCH, DELETE, HEAD, CONNECT, OPTIONS, TRACE")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodTrace:
		w.Write([]byte("TRACE request received\n"))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed\n"))
	}
}

func main() {
	// load tls certificates
	serverTLSCert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
	if err != nil {
		log.Fatalf("Error loading certificate and key file: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}
	server := http.Server{
		Addr:      "localhost:4445",
		Handler:   http.HandlerFunc(httpRequestHandler),
		TLSConfig: tlsConfig,
	}
	defer server.Close()
	log.Fatal(server.ListenAndServeTLS("", ""))
}
