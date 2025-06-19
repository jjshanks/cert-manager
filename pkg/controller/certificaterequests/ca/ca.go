/*
Copyright 2020 The cert-manager Authors.

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

package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificaterequests"
	crutil "github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/util"
	issuerpkg "github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cert-manager/cert-manager/pkg/util/kube"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	CRControllerName = "certificaterequests-issuer-ca"
)

type templateGenerator func(*cmapi.CertificateRequest) (*x509.Certificate, error)
type signingFn func([]*x509.Certificate, crypto.Signer, *x509.Certificate) (pki.PEMBundle, error)

type CA struct {
	issuerOptions      controllerpkg.IssuerOptions
	secretsLister      internalinformers.SecretLister
	certificatesLister cmlisters.CertificateLister

	reporter *crutil.Reporter

	// templateGenerator is used to generate templates to pass to the Go stdlib for signing.
	// It's a member of the struct so it can be mocked for testing.
	templateGenerator templateGenerator

	// signingFn is the function called to actually sign certificates.
	// It's a member of the struct so it can be mocked for testing.
	signingFn signingFn
}

func NewCA(ctx *controllerpkg.Context) certificaterequests.Issuer {
	return &CA{
		issuerOptions:      ctx.IssuerOptions,
		secretsLister:      ctx.KubeSharedInformerFactory.Secrets().Lister(),
		certificatesLister: ctx.SharedInformerFactory.Certmanager().V1().Certificates().Lister(),
		reporter:           crutil.NewReporter(ctx.Clock, ctx.Recorder),
		templateGenerator:  pki.CertificateTemplateFromCertificateRequest,
		signingFn:          pki.SignCSRTemplate,
	}
}

// Sign signs a certificate request. Returns a nil certificate and no error when
// the error is not retryable, i.e., re-running the Sign command will lead to
// the same result. A retryable error would be for example a network failure.
func (c *CA) Sign(ctx context.Context, cr *cmapi.CertificateRequest, issuerObj cmapi.GenericIssuer) (*issuerpkg.IssueResponse, error) {
	log := logf.FromContext(ctx, "sign")

	secretName := issuerObj.GetSpec().CA.SecretName
	resourceNamespace := c.issuerOptions.ResourceNamespace(issuerObj)

	// Check for secret name conflict between certificate and CA issuer
	if conflictDetected := c.validateSecretNameConflict(ctx, cr, secretName, resourceNamespace); conflictDetected {
		return nil, nil
	}

	// get a copy of the CA certificate named on the Issuer
	caCerts, caKey, err := kube.SecretTLSKeyPairAndCA(ctx, c.secretsLister, resourceNamespace, issuerObj.GetSpec().CA.SecretName)
	if k8sErrors.IsNotFound(err) {
		message := fmt.Sprintf("Referenced secret %s/%s not found", resourceNamespace, secretName)

		c.reporter.Pending(cr, err, "SecretMissing", message)
		log.Error(err, message)

		return nil, nil
	}

	if cmerrors.IsInvalidData(err) {
		message := fmt.Sprintf("Failed to parse signing CA keypair from secret %s/%s", resourceNamespace, secretName)

		c.reporter.Pending(cr, err, "SecretInvalidData", message)
		log.Error(err, message)
		return nil, nil
	}

	if err != nil {
		// We are probably in a network error here so we should backoff and retry
		message := fmt.Sprintf("Failed to get certificate key pair from secret %s/%s", resourceNamespace, secretName)
		c.reporter.Pending(cr, err, "SecretGetError", message)
		log.Error(err, message)
		return nil, err
	}

	template, err := c.templateGenerator(cr)
	if err != nil {
		message := "Error generating certificate template"
		c.reporter.Failed(cr, err, "SigningError", message)
		log.Error(err, message)
		return nil, nil
	}

	template.CRLDistributionPoints = issuerObj.GetSpec().CA.CRLDistributionPoints
	template.OCSPServer = issuerObj.GetSpec().CA.OCSPServers
	template.IssuingCertificateURL = issuerObj.GetSpec().CA.IssuingCertificateURLs

	bundle, err := c.signingFn(caCerts, caKey, template)
	if err != nil {
		message := "Error signing certificate"
		c.reporter.Failed(cr, err, "SigningError", message)
		log.Error(err, message)
		return nil, err
	}

	log.V(logf.DebugLevel).Info("certificate issued")

	return &issuerpkg.IssueResponse{
		Certificate: bundle.ChainPEM,
		CA:          bundle.CAPEM,
	}, nil
}

func init() {
	// create certificate request controller for ca issuer
	controllerpkg.Register(CRControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, CRControllerName).
			For(certificaterequests.New(apiutil.IssuerCA, NewCA)).
			Complete()
	})
}

// validateSecretNameConflict checks if the certificate's secretName conflicts with the CA issuer's secretName
// Returns true if a conflict is detected and the request should not be processed further
func (c *CA) validateSecretNameConflict(ctx context.Context, cr *cmapi.CertificateRequest, caSecretName, caSecretNamespace string) bool {
	log := logf.FromContext(ctx, "validateSecretNameConflict")

	// Get the certificate name from the CertificateRequest annotation
	certificateName, exists := cr.Annotations[cmapi.CertificateNameKey]
	if !exists {
		// If there's no certificate name annotation, this might be a direct CertificateRequest
		// or an older version, so we can't perform this validation
		log.V(logf.DebugLevel).Info("CertificateRequest missing certificate name annotation, skipping secret name conflict validation")
		return false
	}

	// Get the certificate object
	cert, err := c.certificatesLister.Certificates(cr.Namespace).Get(certificateName)
	if k8sErrors.IsNotFound(err) {
		log.V(logf.DebugLevel).Info("Certificate not found, skipping secret name conflict validation", "certificateName", certificateName)
		return false
	}
	if err != nil {
		log.Error(err, "Failed to get certificate for secret name conflict validation", "certificateName", certificateName)
		// For lister errors, continue processing - don't block certificate issuance on this validation
		return false
	}

	// Check if the certificate's secretName matches the CA issuer's secretName
	if cert.Spec.SecretName == caSecretName && cr.Namespace == caSecretNamespace {
		message := fmt.Sprintf("Certificate secretName cannot be the same as the CA issuer secretName. The certificate's secretName '%s' conflicts with the CA issuer's secretName '%s'. Please use a different secretName for the certificate.", cert.Spec.SecretName, caSecretName)
		log.Info("Secret name conflict detected", "certificateSecretName", cert.Spec.SecretName, "caSecretName", caSecretName, "namespace", cr.Namespace)
		
		c.reporter.Pending(cr, nil, "SecretNameConflict", message)
		return true // Return true to stop processing, as this is a configuration error
	}

	return false
}
