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
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	corev1 "k8s.io/api/core/v1"

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
		"issuer":                                fmt.Sprintf("%s/%s/%s", h.config.ServerHost, projectID, clusterName),
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

	// Try multiple common field names for the public key data
	publicKeyData, err := h.extractPublicKeyData(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key data: %w", err)
	}

	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	log.Printf("Decoded PEM block type: %s", block.Type)

	// Try different parsing methods based on PEM block type
	rsaPubKey, err := h.parsePublicKeyFromPEM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
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

// extractPublicKeyData tries to extract public key data from the secret using various field names
func (h *Handler) extractPublicKeyData(secret *corev1.Secret) ([]byte, error) {
	// Common field names where public key data might be stored
	fieldNames := []string{
		"tls.crt",               // Standard TLS certificate
		"ca.crt",                // CA certificate
		"public.pem",            // Direct public key PEM
		"sa.pub",                // Service account public key
		"public-key",            // Alternative naming
		"pub",                   // Short form
		"signing.crt",           // Signing certificate
		"signing-key.pub",       // Signing public key
		"token-signing-key.pub", // Token signing public key
		"kube-apiserver.crt",    // API server certificate
		"public",                // Simple public key
	}

	log.Printf("Searching for public key data in secret %s", secret.Name)

	for _, fieldName := range fieldNames {
		if data, exists := secret.Data[fieldName]; exists && len(data) > 0 {
			log.Printf("Found public key data in field %s (%d bytes)", fieldName, len(data))
			return data, nil
		}
	}

	// If no standard field found, list available fields for debugging
	availableFields := make([]string, 0, len(secret.Data))
	for key := range secret.Data {
		availableFields = append(availableFields, key)
	}

	return nil, fmt.Errorf("no public key data found in secret, available fields: %v", availableFields)
}

// parsePublicKeyFromPEM attempts to parse a public key from PEM block using different methods
func (h *Handler) parsePublicKeyFromPEM(block *pem.Block) (*rsa.PublicKey, error) {
	switch block.Type {
	case "CERTIFICATE":
		return h.parseFromCertificate(block.Bytes)
	case "PUBLIC KEY":
		return h.parseFromPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return h.parseFromRSAPublicKey(block.Bytes)
	default:
		log.Printf("Unknown PEM block type %s, trying all parsing methods", block.Type)
		// Try all methods in sequence
		if rsaPubKey, certErr := h.parseFromCertificate(block.Bytes); certErr == nil {
			log.Printf("Successfully parsed as certificate")
			return rsaPubKey, nil
		} else {
			log.Printf("Certificate parsing failed: %v", certErr)
		}

		if rsaPubKey, pkixErr := h.parseFromPublicKey(block.Bytes); pkixErr == nil {
			log.Printf("Successfully parsed as PKIX public key")
			return rsaPubKey, nil
		} else {
			log.Printf("PKIX public key parsing failed: %v", pkixErr)
		}

		if rsaPubKey, pkcs1Err := h.parseFromRSAPublicKey(block.Bytes); pkcs1Err == nil {
			log.Printf("Successfully parsed as PKCS1 RSA public key")
			return rsaPubKey, nil
		} else {
			log.Printf("PKCS1 RSA public key parsing failed: %v", pkcs1Err)
		}

		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// parseFromCertificate extracts RSA public key from x509 certificate
func (h *Handler) parseFromCertificate(data []byte) (*rsa.PublicKey, error) {
	// Validate data length
	if len(data) == 0 {
		return nil, fmt.Errorf("certificate data is empty")
	}

	if len(data) < 10 {
		return nil, fmt.Errorf("certificate data is too short (%d bytes)", len(data))
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if cert.PublicKey == nil {
		return nil, fmt.Errorf("certificate contains no public key")
	}

	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key is not RSA (found: %T)", cert.PublicKey)
	}

	// Validate RSA key size
	if rsaPubKey.Size() < 256 { // 2048 bits minimum
		return nil, fmt.Errorf("RSA key size too small: %d bits", rsaPubKey.Size()*8)
	}

	return rsaPubKey, nil
}

// parseFromPublicKey parses PKIX public key format
func (h *Handler) parseFromPublicKey(data []byte) (*rsa.PublicKey, error) {
	pubKeyInterface, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	rsaPubKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed public key is not RSA")
	}

	return rsaPubKey, nil
}

// parseFromRSAPublicKey parses PKCS#1 RSA public key format
func (h *Handler) parseFromRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	rsaPubKey, err := x509.ParsePKCS1PublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 RSA public key: %w", err)
	}

	return rsaPubKey, nil
}
