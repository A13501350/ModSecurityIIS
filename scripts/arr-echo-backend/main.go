// Minimal echo backend for the ModSecurityIIS ARR body-forward verification.
//
// It exists purely to prove the connector's request body survives the
// connector -> ARR -> backend hand-off intact and without stalling. The
// connector reads the whole request body in OnBeginRequest (DriveBodyRead,
// src/ModSecurityIIS.cpp:635) and re-inserts it via InsertEntityBody
// (:753); ARR then reverse-proxies the request here. If the body is truncated
// on the way, /echo returns a short reply; if it stalls, the client times out.
//
// Standard library only so it runs with `go run` (no go.mod needed).

package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"strconv"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8088", "listen address")
	flag.Parse()

	mux := http.NewServeMux()

	// Liveness check for the probe's readiness wait.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})

	// Echo the *entire* request body back. Content-Length is set to exactly
	// what we received, so the probe can compare response length against the
	// bytes it sent -- a short reply is a truncation, a never-returning call is
	// a stall.
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "backend read error: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	srv := &http.Server{Addr: *addr, Handler: mux, MaxHeaderBytes: 1 << 20}
	log.Printf("arr-echo-backend listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
