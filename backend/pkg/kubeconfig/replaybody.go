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

package kubeconfig

import (
	"bytes"
	"io"
	"net/http"
)

// maxReplayableBodyBytes is the largest request body the cluster proxy keeps in
// memory so it can be sent again. It matches the API server's default
// --max-request-bytes (3 MiB); larger bodies are streamed as before.
const maxReplayableBodyBytes = 3 << 20

// replayableBodyRoundTripper makes each request's body replayable (see
// makeBodyReplayable) before handing it to the base transport. It works on a
// copy, as RoundTrippers must not modify the request they are given.
type replayableBodyRoundTripper struct {
	base http.RoundTripper
}

func (rt replayableBodyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body == nil || req.Body == http.NoBody || req.GetBody != nil {
		return rt.base.RoundTrip(req)
	}

	out := req.Clone(req.Context())
	makeBodyReplayable(out)

	return rt.base.RoundTrip(out)
}

// makeBodyReplayable lets the HTTP transport resend a request's body.
//
// An HTTP/2 server may close a connection with a graceful GOAWAY while a
// request is in flight, which API servers and the load balancers in front of
// them do routinely. The transport then retries the request on a new
// connection, but only if it can rewind the body: without Request.GetBody a
// POST, PUT or PATCH fails ("cannot retry ... after Request.Body was written;
// define Request.GetBody") and the proxy answers 502. Bodyless requests are
// unaffected.
func makeBodyReplayable(req *http.Request) {
	if req.Body == nil || req.Body == http.NoBody || req.GetBody != nil {
		return
	}

	if req.ContentLength > maxReplayableBodyBytes {
		return
	}

	original := req.Body

	buf, err := io.ReadAll(io.LimitReader(original, maxReplayableBodyBytes+1))
	if err != nil || len(buf) > maxReplayableBodyBytes {
		// Too large (unknown length) or unreadable: hand the transport what was
		// read followed by the rest of the stream, which it sends unchanged and
		// cannot retry, as before.
		req.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), original), original}

		return
	}

	_ = original.Close()

	req.Body = io.NopCloser(bytes.NewReader(buf))
	req.ContentLength = int64(len(buf))
	req.TransferEncoding = nil
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
}
