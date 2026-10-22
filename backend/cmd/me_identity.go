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
	"errors"
	"net/http"
	"time"

	"github.com/kubernetes-sigs/headlamp/backend/pkg/auth"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// selfSubjectReviewTimeout bounds the /me identity lookup; the frontend gives
// /me five seconds.
const selfSubjectReviewTimeout = 4 * time.Second

// selfSubjectReviewIdentity resolves the caller of an opaque (non-JWT) bearer
// token by asking the request's cluster who the token belongs to, through the
// SelfSubjectReview API (authentication.k8s.io/v1, Kubernetes 1.28+).
//
// The request is made with the caller's token only: the context's own
// credentials (client certificates, exec plugins, tokens) are dropped, so the
// answer can never describe anyone but the caller.
//
// Statuses: 401 only when the API server rejected the token, so the frontend
// signs the user out only for a token that really is invalid; 404 when the
// cluster does not serve SelfSubjectReview; 503 when the cluster could not be
// reached or answered unexpectedly.
func (c *HeadlampConfig) selfSubjectReviewIdentity(r *http.Request, token string) (*auth.MeIdentity, int, error) {
	contextKey, err := c.getContextKeyForRequest(r)
	if err != nil {
		return nil, http.StatusBadRequest, errors.New("unknown cluster")
	}

	kContext, err := c.KubeConfigStore.GetContext(contextKey)
	if err != nil {
		return nil, http.StatusNotFound, errors.New("unknown cluster")
	}

	restConf, err := kContext.RESTConfig()
	if err != nil {
		return nil, http.StatusServiceUnavailable, errors.New("cluster configuration unavailable")
	}

	callerConf := rest.AnonymousClientConfig(restConf)
	callerConf.BearerToken = token
	callerConf.Timeout = selfSubjectReviewTimeout

	clientset, err := kubernetes.NewForConfig(callerConf)
	if err != nil {
		return nil, http.StatusServiceUnavailable, errors.New("cluster configuration unavailable")
	}

	ctx, cancel := context.WithTimeout(r.Context(), selfSubjectReviewTimeout)
	defer cancel()

	review, err := clientset.AuthenticationV1().SelfSubjectReviews().Create(
		ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{},
	)

	switch {
	case apierrors.IsUnauthorized(err):
		return nil, http.StatusUnauthorized, errors.New("unauthorized")
	case apierrors.IsNotFound(err):
		return nil, http.StatusNotFound, errors.New("identity lookup not supported by this cluster")
	case err != nil:
		return nil, http.StatusServiceUnavailable, errors.New("identity lookup failed")
	}

	return &auth.MeIdentity{
		Username: review.Status.UserInfo.Username,
		Groups:   review.Status.UserInfo.Groups,
	}, http.StatusOK, nil
}
