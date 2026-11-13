// Test cases for the go-no-default-servemux rule (review finding R-14).
// Not compiled: the go tool skips directories whose name starts with a dot.
package mux

import (
	"net"
	"net/http"
	"net/http/httptest"
)

func nilHandler(ln net.Listener) {
	// ruleid: go-no-default-servemux
	http.ListenAndServe("127.0.0.1:8080", nil)
	// ruleid: go-no-default-servemux
	http.ListenAndServeTLS("127.0.0.1:8443", "cert.pem", "key.pem", nil)
	// ruleid: go-no-default-servemux
	http.Serve(ln, nil)
	// ruleid: go-no-default-servemux
	http.ServeTLS(ln, nil, "cert.pem", "key.pem")
}

func explicitDefault(ln net.Listener) {
	// ruleid: go-no-default-servemux
	http.ListenAndServe("127.0.0.1:8080", http.DefaultServeMux)
	srv := &http.Server{
		Addr: "127.0.0.1:8080",
		// ruleid: go-no-default-servemux
		Handler: http.DefaultServeMux,
	}
	// ruleid: go-no-default-servemux
	h := http.Handler(http.DefaultServeMux)
	_, _ = srv, h
}

func serverWithoutHandler(ln net.Listener) {
	// ruleid: go-no-default-servemux
	srv := &http.Server{Addr: "127.0.0.1:8080"}
	srv.Serve(ln)

	// ruleid: go-no-default-servemux
	srv2 := http.Server{
		Addr: "127.0.0.1:8081",
	}
	srv2.Serve(ln)

	// ruleid: go-no-default-servemux
	srv3 := &http.Server{Addr: "127.0.0.1:8082", Handler: nil}
	srv3.Serve(ln)

	if ln != nil {
		// ruleid: go-no-default-servemux
		go http.Serve(ln, nil)
	}
}

func ownMux(ln net.Listener, h http.Handler) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
	// ok: go-no-default-servemux
	http.ListenAndServe("127.0.0.1:8080", mux)
	// ok: go-no-default-servemux
	http.Serve(ln, h)
	// ok: go-no-default-servemux
	srv := &http.Server{Addr: "127.0.0.1:8080", Handler: mux}
	srv.Serve(ln)
	// ok: go-no-default-servemux
	srv2 := http.Server{
		Handler: h,
		Addr:    "127.0.0.1:8081",
	}
	srv2.Serve(ln)

	// ok: go-no-default-servemux
	srv3 := &http.Server{Addr: "127.0.0.1:8082"}
	srv3.Handler = mux
	srv3.Serve(ln)

	// ok: go-no-default-servemux
	srv4 := http.Server{Addr: "127.0.0.1:8083"}
	srv4.Handler = h
	srv4.Serve(ln)

	// ok: go-no-default-servemux
	ts := httptest.NewServer(mux)
	defer ts.Close()
}
