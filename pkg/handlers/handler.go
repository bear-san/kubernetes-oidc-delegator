// Package handlers provides HTTP handlers for the OIDC delegator API
package handlers

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/bear-san/kubernetes-oidc-delegator/internal/config"
	"github.com/bear-san/kubernetes-oidc-delegator/pkg/kubernetes"
)

type Handler struct {
	k8sClient *kubernetes.Client
	config    *config.Config
}

func NewHandler(k8sClient *kubernetes.Client, cfg *config.Config) *Handler {
	return &Handler{
		k8sClient: k8sClient,
		config:    cfg,
	}
}

func (h *Handler) GetOpenIDConfiguration(c *gin.Context) {
	projectID := c.Param("projectID")
	clusterName := c.Param("clusterName")

	if projectID == "" || clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project ID and cluster name are required"})
		return
	}

	configuration := map[string]interface{}{
		"issuer":                                "https://kubernetes.default.svc.cluster.local",
		"jwks_uri":                              fmt.Sprintf("%s/%s/%s/keys", h.config.ServerHost, projectID, clusterName),
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}

	c.JSON(http.StatusOK, configuration)
}

func (h *Handler) GetJWKs(c *gin.Context) {
	projectID := c.Param("projectID")
	clusterName := c.Param("clusterName")

	if projectID == "" || clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project ID and cluster name are required"})
		return
	}

	namespace := h.config.FormatNamespace(projectID)

	rsaPubKey, err := h.getPublicKeyFromSecret(namespace, clusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get public key: %v", err)})
		return
	}

	publicKeyset, err := h.createJWKS(rsaPubKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create JWKS: %v", err)})
		return
	}

	c.JSON(http.StatusOK, publicKeyset)
}

func (h *Handler) getPublicKeyFromSecret(namespace, clusterName string) (*rsa.PublicKey, error) {
	ctx := context.Background()

	secret, err := h.k8sClient.GetServiceAccountSecret(ctx, namespace, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	publicKeyData, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, fmt.Errorf("public key not found in secret")
	}

	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	return rsaPubKey, nil
}

func (h *Handler) createJWKS(rsaPubKey *rsa.PublicKey) (jwk.Set, error) {
	key, err := jwk.FromRaw(rsaPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}

	if configErr := h.configureJWK(key); configErr != nil {
		return nil, fmt.Errorf("failed to configure JWK: %w", configErr)
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate thumbprint: %w", err)
	}

	kid := base64.RawURLEncoding.EncodeToString(thumbprint)
	if setErr := key.Set(jwk.KeyIDKey, kid); setErr != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", setErr)
	}

	publicKey, err := jwk.PublicRawKeyOf(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	publicJWK, err := jwk.FromRaw(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create public JWK: %w", err)
	}

	if err := h.configureJWK(publicJWK); err != nil {
		return nil, fmt.Errorf("failed to configure public JWK: %w", err)
	}

	if err := publicJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("failed to set public key ID: %w", err)
	}

	publicKeyset := jwk.NewSet()
	if err := publicKeyset.AddKey(publicJWK); err != nil {
		return nil, fmt.Errorf("failed to add public key to set: %w", err)
	}

	return publicKeyset, nil
}

func (h *Handler) configureJWK(key jwk.Key) error {
	if err := key.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return fmt.Errorf("failed to set algorithm: %w", err)
	}

	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return fmt.Errorf("failed to set key usage: %w", err)
	}

	return nil
}
