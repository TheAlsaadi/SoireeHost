// Test cases for the go-no-public-listener rule (S-01). Not compiled: the go
// tool skips directories whose name starts with a dot.
package listeners

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
)

func plainListen(port string) {
	// ruleid: go-no-public-listener
	net.Listen("tcp", "0.0.0.0:8080")
	// ruleid: go-no-public-listener
	net.Listen("tcp", ":8080")
	// ruleid: go-no-public-listener
	net.Listen("tcp", ":"+port)
	// ruleid: go-no-public-listener
	net.Listen("tcp6", "[::]:443")
	// ruleid: go-no-public-listener
	net.Listen("tcp", "192.168.1.20:80")
	// ruleid: go-no-public-listener
	net.Listen("tcp", "localhost:8080")
	// ruleid: go-no-public-listener
	net.Listen("tcp", "0.0.0.0:"+port)
	// ruleid: go-no-public-listener
	net.Listen("tcp", net.JoinHostPort("", port))
	// ruleid: go-no-public-listener
	net.Listen("tcp", net.JoinHostPort("::", port))
	// ruleid: go-no-public-listener
	net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
	// ruleid: go-no-public-listener
	net.Listen("tcp", fmt.Sprintf(":%s", port))

	// ok: go-no-public-listener
	net.Listen("tcp", "127.0.0.1:0")
	// ok: go-no-public-listener
	net.Listen("tcp", "[::1]:8443")
	// ok: go-no-public-listener
	net.Listen("tcp", "127.0.0.1:"+port)
	// ok: go-no-public-listener
	net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	// ok: go-no-public-listener
	net.Listen("tcp", net.JoinHostPort("::1", port))
	// ok: go-no-public-listener
	net.Listen("tcp", fmt.Sprintf("127.0.0.1:%s", port))
	// ruleid: go-no-public-listener
	net.Listen("tcp", "0.0.0.0"+":"+port)
	// ok: go-no-public-listener
	net.Listen("tcp", "127.0.0.1"+":"+port)
}

func hostFromVariable(host, port string) {
	// ok: go-no-public-listener
	net.Listen("tcp", fmt.Sprintf("%s:%s", host, port))
	// ok: go-no-public-listener
	net.Listen("tcp", host+":"+port)
}

func throughVariables(port string) {
	addr := ":9000"
	// ruleid: go-no-public-listener
	net.Listen("tcp", addr)

	safe := "127.0.0.1:9000"
	// ok: go-no-public-listener
	net.Listen("tcp", safe)

	if port != "" {
		for i := 0; i < 2; i++ {
			// ruleid: go-no-public-listener
			ln, err := net.Listen("tcp", "0.0.0.0:"+port)
			_, _ = ln, err
		}
	}
}

func listenConfig(ctx context.Context) {
	lc := net.ListenConfig{}
	// ruleid: go-no-public-listener
	lc.Listen(ctx, "tcp", ":8080")
	// ok: go-no-public-listener
	lc.Listen(ctx, "tcp", "127.0.0.1:0")

	var lc2 net.ListenConfig
	// ruleid: go-no-public-listener
	lc2.Listen(ctx, "tcp", "[::]:8080")
	// ruleid: go-no-public-listener
	lc2.ListenPacket(ctx, "udp", ":53")
	// ok: go-no-public-listener
	lc2.ListenPacket(ctx, "udp", "[::1]:53")
}

func packets() {
	// ruleid: go-no-public-listener
	net.ListenPacket("udp", ":53")
	// ruleid: go-no-public-listener
	net.ListenPacket("udp4", "0.0.0.0:5353")
	// ok: go-no-public-listener
	net.ListenPacket("udp", "127.0.0.1:0")
}

func httpServers(h http.Handler) {
	// ruleid: go-no-public-listener
	http.ListenAndServe(":8080", h)
	// ruleid: go-no-public-listener
	http.ListenAndServeTLS("0.0.0.0:443", "cert.pem", "key.pem", h)
	// ok: go-no-public-listener
	http.ListenAndServe("127.0.0.1:8080", h)
	// ok: go-no-public-listener
	http.ListenAndServeTLS("[::1]:8443", "cert.pem", "key.pem", h)

	srv := &http.Server{
		// ruleid: go-no-public-listener
		Addr:    ":8080",
		Handler: h,
	}
	srv2 := http.Server{
		Handler: h,
		// ruleid: go-no-public-listener
		Addr: "0.0.0.0:80",
	}
	srv3 := &http.Server{
		// ok: go-no-public-listener
		Addr:    "127.0.0.1:8080",
		Handler: h,
	}
	// ruleid: go-no-public-listener
	srv.Addr = "[::]:80"
	// ok: go-no-public-listener
	srv3.Addr = "[::1]:80"
	// ruleid: go-no-public-listener
	srv2.Addr = ":443"
}

func unrelated(addr, path, sddl string) {
	// ok: go-no-public-listener
	net.Dial("tcp", "example.com:443")
	// ok: go-no-public-listener
	ipc.Listen(path, sddl)
	// ok: go-no-public-listener
	net.Listen("tcp", addr)
	// ok: go-no-public-listener
	fmt.Println(":8080")
}
