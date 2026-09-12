package main

import (
	"flag"
	"fmt"
	"net/http"
)

func main() {
	address := flag.String("address", "127.0.0.1:19090", "listen address")
	flag.Parse()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/benchmark" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "13")
		_, _ = fmt.Fprint(w, "benchmark-ok\n")
	})
	server := &http.Server{Addr: *address, Handler: handler}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
