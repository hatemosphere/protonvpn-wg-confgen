package api

import (
	"bufio"
	"bytes"
	_ "embed" // for the captured ClientHello
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
	"unicode/utf16"

	utls "github.com/refraction-networking/utls"
)

// This file reproduces, byte for byte, what the official ProtonVPN Linux client
// puts on the wire. That client is python-proton-core on aiohttp and OpenSSL;
// the reference here is Ubuntu 24.04's stock packages (aiohttp 3.9.1, OpenSSL
// 3.0.13), matching the distribution named in the User-Agent. net/http cannot
// do this: it sorts headers, canonicalizes their names and has its own TLS
// handshake, so requests are written by hand over a uTLS connection.

// Field is one key of a JSON object body.
type Field struct {
	Key   string
	Value any
}

// Body is a JSON object whose keys keep their order. Python dicts are ordered
// and the official client's bodies go out in insertion order, which a Go map
// cannot express.
type Body []Field

// encode renders the body the way Python's json.dumps does by default: ", " and
// ": " separators and every non-ASCII character escaped.
func (b Body) encode() []byte {
	var buf bytes.Buffer
	writePyValue(&buf, b)
	return buf.Bytes()
}

func writePyValue(buf *bytes.Buffer, v any) {
	switch v := v.(type) {
	case Body:
		buf.WriteByte('{')
		for i, f := range v {
			if i > 0 {
				buf.WriteString(", ")
			}
			writePyString(buf, f.Key)
			buf.WriteString(": ")
			writePyValue(buf, f.Value)
		}
		buf.WriteByte('}')
	case string:
		writePyString(buf, v)
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case int:
		buf.WriteString(strconv.Itoa(v))
	default:
		// Not a type any request uses; fall back rather than drop the value.
		raw, _ := json.Marshal(v)
		buf.Write(raw)
	}
}

// writePyString escapes like json.dumps with ensure_ascii: only printable ASCII
// goes out literally, and astral characters become UTF-16 surrogate pairs.
func writePyString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r >= 0x20 && r <= 0x7e:
			buf.WriteRune(r)
		case r > 0xffff:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
		default:
			fmt.Fprintf(buf, `\u%04x`, r)
		}
	}
	buf.WriteByte('"')
}

// headerOrder is the order aiohttp emits headers in, after the Host line: the
// session's own headers, then per-request ones, then aiohttp's defaults, then
// the body headers. Names are sent exactly as spelled here.
var headerOrder = []string{
	"x-pm-appversion",
	"User-Agent",
	"x-pm-uid",
	"Authorization",
	timezoneHeader,
	hvTokenHeader,
	hvTokenTypeHeader,
	"Accept",
	"Accept-Encoding",
	"Content-Length",
	"Content-Type",
}

// clientHello is a TLS ClientHello recorded from aiohttp 3.9.1 on OpenSSL
// 3.0.13 with ssl.create_default_context(), as python-proton-core configures it.
//
//go:embed clienthello_ubuntu2404.bin
var clientHello []byte

// wireTransport sends each request on its own connection, as the official
// client does: it opens a new aiohttp ClientSession per API call. Proxies from
// the environment are not used, since aiohttp ignores them by default too.
type wireTransport struct{}

// NewHTTPClient returns a client whose requests are indistinguishable on the
// wire from the official Linux client's.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: wireTransport{}}
}

func (wireTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	secure := req.URL.Scheme == "https"
	addr := req.URL.Host
	if req.URL.Port() == "" {
		port := "80"
		if secure {
			port = "443"
		}
		addr = net.JoinHostPort(req.URL.Hostname(), port)
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(req.Context(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := req.Context().Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if secure {
		conn, err = handshake(req, conn)
		if err != nil {
			return nil, err
		}
	}

	if err := writeRequest(conn, req); err != nil {
		_ = conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp.Body = &connBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// handshake performs TLS with the recorded OpenSSL ClientHello. Certificate
// verification is uTLS's normal one against the system roots.
func handshake(req *http.Request, conn net.Conn) (net.Conn, error) {
	// A spec is consumed by the connection it is applied to, so build one each time.
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(clientHello)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to load TLS fingerprint: %w", err)
	}
	tlsConn := utls.UClient(conn, &utls.Config{ServerName: req.URL.Hostname()}, utls.HelloCustom)
	if err := tlsConn.ApplyPreset(spec); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to apply TLS fingerprint: %w", err)
	}
	if err := tlsConn.HandshakeContext(req.Context()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func writeRequest(w io.Writer, req *http.Request) error {
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			return err
		}
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.URL.Host)
	for _, name := range headerOrder {
		if name == "Content-Length" {
			if body != nil {
				fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
			}
			continue
		}
		if values := req.Header[name]; len(values) > 0 {
			fmt.Fprintf(&buf, "%s: %s\r\n", name, values[0])
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)

	_, err := w.Write(buf.Bytes())
	return err
}

// connBody closes the connection once the response body is done with.
type connBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *connBody) Close() error {
	err := b.ReadCloser.Close()
	if cerr := b.conn.Close(); err == nil {
		err = cerr
	}
	return err
}
