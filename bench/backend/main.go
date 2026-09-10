// Minimal backend for the v2-vs-v3 IIS connector benchmark.
//
// It exists so the measured cost is the WAF, not the origin: a fast,
// allocation-light Go server that answers with fixed-size bodies and echoes
// POST payloads. Runs on 127.0.0.1:8080; the IIS site under test reverse
// proxies to it via ARR (same topology scripts/ci-crs.ps1 uses with albedo).
//
// Only the standard library is used so it can be started with
// `go run ./bench/backend/main.go` without a go.mod.

package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	small := strings.Repeat("s", 128)
	big := strings.Repeat("b", 65536)

	write := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(200)
		_, _ = io.WriteString(w, body)
	}

	mux := http.NewServeMux()

	// S1/S2: tiny response, only the request path is inspected.
	mux.HandleFunc("/bench/small", func(w http.ResponseWriter, r *http.Request) {
		write(w, small)
	})

	// S5: 64 KiB response, exercises phase 3/4 (response body inspection).
	mux.HandleFunc("/bench/big", func(w http.ResponseWriter, r *http.Request) {
		write(w, big)
	})

	// S3/S4: echo the request body back so the response proves the body
	// arrived intact (and so a truncated body is visible as a short reply).
	mux.HandleFunc("/bench/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		write(w, string(body))
	})

	// S6: benign response; a benchmark rule blocks this path, so the
	// intervention path (not just the pass path) is measured.
	mux.HandleFunc("/bench/block", func(w http.ResponseWriter, r *http.Request) {
		write(w, small)
	})

	// S7/S8: read the request body, discard it, and answer with the same
	// tiny body as /bench/small. Compared against /bench/echo this separates
	// a request-body problem from a response-body one: if a POST hangs here
	// too, the request side is at fault; if it only hangs on /bench/echo, the
	// response side is.
	mux.HandleFunc("/bench/discard", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		write(w, small)
	})

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		// Keep the origin from becoming the bottleneck at high concurrency.
		MaxHeaderBytes: 1 << 20,
	}
	log.Printf("bench backend listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
