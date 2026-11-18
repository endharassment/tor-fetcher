package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var parallelism = flag.Int("p", 1, "Parallelism")

var length = flag.Int("l", 32, "Length")

var target = flag.String("target", "", "The URL to retrieve (required)")

var ua = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0", "Tor user agent by default")

var socksAddr = flag.String("proxy", "socks5://127.0.0.1:9050", "SOCKS5 proxy address for Tor")

var debug = flag.Bool("debug", false, "Enable debug logging")

var method = flag.String("method", "GET", "HTTP request method, e.g. HEAD")

var trace = flag.Bool("trace", false, "Print the request/redirect/challenge chain to stderr")

var postData = flag.String("data", "", "application/x-www-form-urlencoded POST body, e.g. \"foo=bar&baz=qux\"")

var cookieIn = flag.String("cookie", "", "Read cookies for --target's host from this JSON file before fetching (see --cookie-jar)")

var cookieOut = flag.String("cookie-jar", "", "Write cookies for --target's host to this JSON file after fetching")

func init() {
	// Curl-style alias for --method.
	flag.StringVar(method, "X", "GET", "alias for --method")
	// Curl-style alias for --data.
	flag.StringVar(postData, "d", "", "alias for --data")
	// Curl-style alias for --cookie.
	flag.StringVar(cookieIn, "b", "", "alias for --cookie")
	// Curl-style alias for --cookie-jar.
	flag.StringVar(cookieOut, "c", "", "alias for --cookie-jar")
}

// tracef prints a line to stderr describing a step in the fetch chain when
// --trace is enabled. Unlike --debug it is concise and aimed at following
// redirects and challenges.
func tracef(format string, args ...any) {
	if *trace {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func main() {
	flag.Parse()
	if *debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}
	targetURL, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("parsing --target: %v", err)
	}

	tc := NewTorClient()
	if *cookieIn != "" {
		if err := loadCookies(*cookieIn, tc.c.Jar, targetURL); err != nil {
			log.Fatalf("loading --cookie: %v", err)
		}
	}
	resp, err := tc.Fetch(*target, "", []byte(*postData))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if *cookieOut != "" {
		if err := saveCookies(*cookieOut, tc.c.Jar, resp.Request.URL); err != nil {
			log.Fatalf("saving --cookie-jar: %v", err)
		}
	}

	// Surface the status line and headers on stderr for non-200 responses
	// (and HEAD, which has no body) so failures and probes are debuggable.
	if resp.StatusCode != http.StatusOK || strings.EqualFold(*method, "HEAD") {
		fmt.Fprintf(os.Stderr, "HTTP %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		resp.Header.Write(os.Stderr)
		fmt.Fprintln(os.Stderr)
	}

	body, err := decodeBody(resp)
	if err != nil {
		log.Fatal(err)
	}
	// Print the body even on errors so the actual content is visible.
	os.Stdout.Write(body)

	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
