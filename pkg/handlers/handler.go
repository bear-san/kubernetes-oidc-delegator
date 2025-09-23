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

	"github.com/bear-san/kubernetes-oidc-delegator/internal/config"
	"github.com/bear-san/kubernetes-oidc-delegator/pkg/kubernetes"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
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

	ctx := context.Background()
	secret, err := h.k8sClient.GetServiceAccountSecret(ctx, namespace, clusterName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("failed to get secret: %v", err)})
		return
	}

	publicKeyData, ok := secret.Data["tls.crt"]
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "public key not found in secret"})
		return
	}

	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode PEM block"})
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to parse certificate: %v", err)})
		return
	}

	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "public key is not RSA"})
		return
	}

	key, err := jwk.FromRaw(rsaPubKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create JWK: %v", err)})
		return
	}

	if err := key.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set algorithm"})
		return
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set key usage"})
		return
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate thumbprint"})
		return
	}
	kid := base64.RawURLEncoding.EncodeToString(thumbprint)
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set key ID"})
		return
	}

	keyset := jwk.NewSet()
	if err := keyset.AddKey(key); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add key to set"})
		return
	}

	publicKey, err := jwk.PublicRawKeyOf(key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get public key"})
		return
	}

	publicJWK, err := jwk.FromRaw(publicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create public JWK"})
		return
	}

	publicJWK.Set(jwk.AlgorithmKey, "RS256")
	publicJWK.Set(jwk.KeyUsageKey, "sig")
	publicJWK.Set(jwk.KeyIDKey, kid)

	publicKeyset := jwk.NewSet()
	publicKeyset.AddKey(publicJWK)

	c.JSON(http.StatusOK, publicKeyset)
}
