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

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/kubeconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd/api"
)

const selfSubjectReviewPath = "/apis/authentication.k8s.io/v1/selfsubjectreviews"

// meIdentityRequest is a /me request for cluster "main" carrying token.
func meIdentityRequest(token string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/main/me", nil)
	req = mux.SetURLVars(req, map[string]string{"clusterName": "main"})
	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

func newMeIdentityConfig(t *testing.T, server string) *HeadlampConfig {
	t.Helper()

	return newDrainAuthConfig(t, &kubeconfig.Context{
		Name:    "main",
		Cluster: &api.Cluster{Server: server, InsecureSkipTLSVerify: true},
		// The context's own credential must never be sent for the caller.
		AuthInfo: &api.AuthInfo{Token: "context-own-token"},
	})
}

func TestSelfSubjectReviewIdentity_UsesOnlyTheCallersToken(t *testing.T) {
	kubeAPI := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, selfSubjectReviewPath, r.URL.Path)
		assert.Equal(t, "Bearer opaque-user-token", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(authenticationv1.SelfSubjectReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"},
			Status: authenticationv1.SelfSubjectReviewStatus{UserInfo: authenticationv1.UserInfo{
				Username: "doks-admin",
				Groups:   []string{"system:masters", "system:authenticated"},
			}},
		}))
	}))
	t.Cleanup(kubeAPI.Close)

	identity, status, err := newMeIdentityConfig(t, kubeAPI.URL).
		selfSubjectReviewIdentity(meIdentityRequest("opaque-user-token"), "opaque-user-token")

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "doks-admin", identity.Username)
	assert.Equal(t, []string{"system:masters", "system:authenticated"}, identity.Groups)
}

func TestSelfSubjectReviewIdentity_StatusMapping(t *testing.T) {
	cases := []struct {
		name       string
		apiStatus  int32
		wantStatus int
	}{
		{"rejected token", http.StatusUnauthorized, http.StatusUnauthorized},
		{"API not served", http.StatusNotFound, http.StatusNotFound},
		{"forbidden is not a sign-out", http.StatusForbidden, http.StatusServiceUnavailable},
		{"server error", http.StatusInternalServerError, http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kubeAPI := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(int(tc.apiStatus))
				require.NoError(t, json.NewEncoder(w).Encode(metav1.Status{
					TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
					Status:   metav1.StatusFailure,
					Code:     tc.apiStatus,
					Reason:   metav1.StatusReason(http.StatusText(int(tc.apiStatus))),
				}))
			}))
			t.Cleanup(kubeAPI.Close)

			identity, status, err := newMeIdentityConfig(t, kubeAPI.URL).
				selfSubjectReviewIdentity(meIdentityRequest("opaque-user-token"), "opaque-user-token")

			require.Error(t, err)
			assert.Nil(t, identity)
			assert.Equal(t, tc.wantStatus, status)
		})
	}
}

func TestSelfSubjectReviewIdentity_UnreachableCluster(t *testing.T) {
	kubeAPI := httptest.NewTLSServer(http.NotFoundHandler())
	url := kubeAPI.URL
	kubeAPI.Close()

	_, status, err := newMeIdentityConfig(t, url).
		selfSubjectReviewIdentity(meIdentityRequest("opaque-user-token"), "opaque-user-token")

	require.Error(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, status)
}
