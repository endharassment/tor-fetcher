package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
)

// jsonCookie is the on-disk shape used by --cookie/--cookie-jar. It carries
// just enough of http.Cookie to round-trip a session between separate
// tor-fetcher invocations (e.g. fetch a page to establish a session and CSRF
// token, then POST a form using that same session).
type jsonCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// loadCookies reads cookies from path and installs them into jar for u's
// origin, so a subsequent Fetch(u, ...) reuses the session.
func loadCookies(path string, jar http.CookieJar, u *url.URL) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cookies []jsonCookie
	if err := json.Unmarshal(data, &cookies); err != nil {
		return err
	}
	httpCookies := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		httpCookies = append(httpCookies, &http.Cookie{Name: c.Name, Value: c.Value})
	}
	jar.SetCookies(u, httpCookies)
	return nil
}

// saveCookies writes jar's cookies for u's origin to path as JSON.
func saveCookies(path string, jar http.CookieJar, u *url.URL) error {
	var cookies []jsonCookie
	for _, c := range jar.Cookies(u) {
		cookies = append(cookies, jsonCookie{Name: c.Name, Value: c.Value})
	}
	data, err := json.MarshalIndent(cookies, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
