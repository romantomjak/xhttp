# xhttp

xhttp is a drop-in replacement for `http.ListenAndServe` with sensible
defaults and support for common middlewares.

---

Example usage 👇

```go
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/romantomjak/xhttp"
)

func main() {
	mux := http.NewServeMux()

	// Use request scoped values in handlers.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		slog := xhttp.SlogFromContext(r.Context())
		slog.Info("Serving index page")

		ip := xhttp.ClientIPFromContext(r.Context())
		fmt.Fprintf(w, "Hi %s!\n", ip)
	})

	// Built-in support for common middlewares.
	var h http.Handler = mux
	h = xhttp.Gzip(h)
	h = xhttp.ClientIP(h, xhttp.TrustedHeaderCfConnectingIP)
	h = xhttp.Slog(h)

	if err := xhttp.ListenAndServe("127.0.0.1:8000", h); err != nil {
		slog.Error("listen and serve", "err", err)
		os.Exit(-1)
	}
}
```

## Contributing

Code patches are welcome, but to make sure things are well coordinated, please file an issue first to discuss the change before starting the work. It`s recommended that you signal your intention to contribute by filing a new issue or by claiming an existing one.

## License

MIT
