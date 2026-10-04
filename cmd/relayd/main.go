// Command relayd runs the strict HTTP/1.1 GET/POST TCP reverse proxy.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/relay/relay"
)

func main() {
	listen := flag.String("listen", ":8080", "downstream listen address")
	upstream := flag.String("upstream", "", "fixed upstream TCP address (required)")
	idle := flag.Duration("idle-timeout", 60*time.Second, "idle timeout on either transport")
	dial := flag.Duration("dial-timeout", 10*time.Second, "upstream dial timeout")
	flag.Parse()

	if *upstream == "" {
		log.Fatal("relayd: -upstream is required")
	}

	srv, err := relay.NewServer(relay.Config{
		Listen:      *listen,
		Upstream:    *upstream,
		IdleTimeout: *idle,
		DialTimeout: *dial,
		Journal:     relay.StdLogger{L: log.New(os.Stderr, "relay ", log.LstdFlags|log.Lmicroseconds)},
	})
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	log.Printf("relayd listening on %s -> upstream %s", ln.Addr(), *upstream)

	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Fatalf("serve: %v", err)
		}
	}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	log.Printf("shutting down")
	_ = ln.Close()
	time.Sleep(50 * time.Millisecond)
}
