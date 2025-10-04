// Package handlers provides HTTP handlers for the OIDC delegator API
package handlers

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/bear-san/kubernetes-oidc-delegator/internal/config"
)

type Handler struct {
	config    *config.Config
	publicKey *rsa.PublicKey
}

func NewHandler(cfg *config.Config) *Handler {
	h := &Handler{
		config: cfg,
	}

	// Load public key on initialization
	if err := h.loadPublicKey(); err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	return h
}

func (h *Handler) loadPublicKey() error {
	// Read the public key file
	publicKeyData, err := os.ReadFile(h.config.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	// Parse the PEM block
	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from public key file")
	}

	log.Printf("Decoded PEM block type: %s", block.Type)

	// Parse the public key
	rsaPubKey, err := h.parsePublicKeyFromPEM(block)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	h.publicKey = rsaPubKey
	return nil
}

func (h *Handler) GetOpenIDConfiguration(c *gin.Context) {
	configuration := map[string]interface{}{
		"issuer":                                h.config.Issuer,
		"jwks_uri":                              fmt.Sprintf("%s/keys", h.config.ServerHost),
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}

	c.JSON(http.StatusOK, configuration)
}

func (h *Handler) GetJWKs(c *gin.Context) {
	publicKeyset, err := h.createJWKS(h.publicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create JWKS: %v", err)})
		return
	}

	c.JSON(http.StatusOK, publicKeyset)
}

func (h *Handler) createJWKS(rsaPubKey *rsa.PublicKey) (jwk.Set, error) {
	key, err := jwk.FromRaw(rsaPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}

	if configErr := h.configureJWK(key); configErr != nil {
		return nil, fmt.Errorf("failed to configure JWK: %w", configErr)
	}

	// Generate kid using Kubernetes-compatible method:
	// Serialize public key in DER format, take SHA256 hash, then urlsafe base64-encode
	kid, err := h.generateKubernetesCompatibleKID(rsaPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate kid: %w", err)
	}

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

// generateKubernetesCompatibleKID generates a kid (Key ID) using Kubernetes-compatible method:
// Serialize public key in DER format, take SHA256 hash, then urlsafe base64-encode
func (h *Handler) generateKubernetesCompatibleKID(pubKey *rsa.PublicKey) (string, error) {
	// Serialize the RSA public key to DER format using PKIX format
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key to DER: %w", err)
	}

	// Take SHA256 hash of the DER-encoded public key
	hash := sha256.Sum256(derBytes)

	// URLSafe base64-encode the hash (without padding)
	kid := base64.RawURLEncoding.EncodeToString(hash[:])

	log.Printf("Generated Kubernetes-compatible kid: %s", kid)

	return kid, nil
}
