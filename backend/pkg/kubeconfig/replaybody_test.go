/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubeconfig_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kubernetes-sigs/headlamp/backend/pkg/kubeconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"k8s.io/client-go/tools/clientcmd/api"
)

// goAwayServer is a minimal HTTP/2 API server that answers the first request
// it receives with a graceful GOAWAY (last stream 0: "not processed, retry
// elsewhere"), as an API server or its load balancer does when it closes a
// connection, and serves every later connection normally. It records the
// request bodies it served.
type goAwayServer struct {
	listener net.Listener

	mu       sync.Mutex
	conns    int
	received []string
}

func newGoAwayServer(t *testing.T) *goAwayServer {
	t.Helper()

	certSource := httptest.NewUnstartedServer(nil)
	certSource.StartTLS()
	certs := certSource.TLS.Certificates
	certSource.Close()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: certs,
		NextProtos:   []string{http2.NextProtoTLS},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)

	s := &goAwayServer{listener: listener}

	t.Cleanup(func() { _ = listener.Close() })

	go s.serve()

	return s
}

func (s *goAwayServer) URL() string { return "https://" + s.listener.Addr().String() }

func (s *goAwayServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.mu.Lock()
		s.conns++
		first := s.conns == 1
		s.mu.Unlock()

		go s.handle(conn, first)
	}
}

func (s *goAwayServer) handle(conn net.Conn, goAway bool) {
	defer func() { _ = conn.Close() }()

	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}

	framer := http2.NewFramer(conn, conn)
	if framer.WriteSettings() != nil {
		return
	}

	bodies := map[uint32]*bytes.Buffer{}

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return
		}

		var streamID uint32

		ended := false

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() && framer.WriteSettingsAck() != nil {
				return
			}

			continue
		case *http2.PingFrame:
			if !f.IsAck() && framer.WritePing(true, f.Data) != nil {
				return
			}

			continue
		case *http2.HeadersFrame:
			streamID, ended = f.StreamID, f.StreamEnded()
			bodies[streamID] = &bytes.Buffer{}
		case *http2.DataFrame:
			streamID, ended = f.StreamID, f.StreamEnded()
			_, _ = bodies[streamID].Write(f.Data())
		default:
			continue
		}

		if !ended {
			continue
		}

		if goAway {
			_ = framer.WriteGoAway(0, http2.ErrCodeNo, nil)
			return
		}

		if !s.respond(framer, streamID, bodies[streamID].String()) {
			return
		}
	}
}

// respond records body and answers the stream with a 201.
func (s *goAwayServer) respond(framer *http2.Framer, streamID uint32, body string) bool {
	s.mu.Lock()
	s.received = append(s.received, body)
	s.mu.Unlock()

	var headers bytes.Buffer

	enc := hpack.NewEncoder(&headers)
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "201"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})

	if framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: headers.Bytes(), EndHeaders: true,
	}) != nil {
		return false
	}

	return framer.WriteData(streamID, true, []byte(`{"kind":"SelfSubjectReview"}`)) == nil
}

func (s *goAwayServer) bodies() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.received...)
}

// A POST that the API server answers with a graceful GOAWAY is retried on a new
// connection with its body, instead of failing with "cannot retry ... after
// Request.Body was written".
func TestProxyRetriesRequestBodyAfterGoAway(t *testing.T) {
	server := newGoAwayServer(t)

	ctx := &kubeconfig.Context{
		Name:    "goaway",
		Cluster: &api.Cluster{Server: server.URL(), InsecureSkipTLSVerify: true},
	}

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`
	// Like a request the server received: a body stream with no way to rewind it.
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/apis/authentication.k8s.io/v1/selfsubjectreviews", io.NopCloser(strings.NewReader(body)))
	request.ContentLength = int64(len(body))
	request.RequestURI = ""
	require.Nil(t, request.GetBody)

	recorder := httptest.NewRecorder()
	require.NoError(t, ctx.ProxyRequest(recorder, request))

	assert.Equal(t, http.StatusCreated, recorder.Code)
	assert.Equal(t, []string{body}, server.bodies())
}

func TestProxyStreamsBodiesOverTheReplayLimit(t *testing.T) {
	var received int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		assert.NoError(t, err)

		received = int(n)

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	ctx := &kubeconfig.Context{Name: "large", Cluster: &api.Cluster{Server: server.URL}}

	const size = 4 << 20 // over the 3 MiB replay limit, length unknown to the proxy

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/api",
		io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), size))))
	require.NoError(t, err)

	request.ContentLength = -1

	recorder := httptest.NewRecorder()
	require.NoError(t, ctx.ProxyRequest(recorder, request))

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, size, received)
}
