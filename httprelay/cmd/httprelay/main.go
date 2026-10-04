// Command httprelay 启动一个固定上游的 HTTP/1.1 TCP 反向代理。
//
// 仅支持 GET、POST；无 TLS、Upgrade、CONNECT。
//
// 用法：
//
//	httprelay -listen 127.0.0.1:8080 -upstream 127.0.0.1:9000
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"httprelay"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:8080", "下游监听地址")
	upstream := flag.String("upstream", "127.0.0.1:9000", "固定上游源站地址 (host:port)")
	flag.Parse()

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *listenAddr, err)
	}
	p := httprelay.New(*upstream)
	logger := log.New(os.Stderr, "httprelay ", log.LstdFlags|log.Lmicroseconds)
	p.SetLogger(logger)
	logger.Printf("listening on %s, upstream %s", ln.Addr(), *upstream)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := p.Serve(ctx, ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
	logger.Print("stopped")
}
