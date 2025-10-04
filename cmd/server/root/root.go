// Package root provides the root command for the kubernetes-oidc-delegator server
package root

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"

	"github.com/bear-san/kubernetes-oidc-delegator/internal/config"
	"github.com/bear-san/kubernetes-oidc-delegator/pkg/handlers"
)

var (
	port          string
	publicKeyPath string
	serverHost    string
	issuer        string
)

var rootCmd = &cobra.Command{
	Use:   "kubernetes-oidc-delegator",
	Short: "OIDC token verification API for Kubernetes ServiceAccounts",
	Long: `A server that provides JWKs endpoint for external validation
of tokens issued to Kubernetes ServiceAccounts`,
	Run: runServer,
}

func init() {
	rootCmd.Flags().StringVarP(&port, "port", "p", "8080", "Server port")
	rootCmd.Flags().StringVar(&publicKeyPath, "public-key", "", "Path to the public key file (PEM format)")
	rootCmd.Flags().StringVar(&serverHost, "server-host", "", "Server host URL (required)")
	rootCmd.Flags().StringVar(&issuer, "issuer", "https://kubernetes.default.svc.cluster.local", "Token issuer URL")

	if err := rootCmd.MarkFlagRequired("server-host"); err != nil {
		panic(fmt.Sprintf("failed to mark required flag: %v", err))
	}

	if err := rootCmd.MarkFlagRequired("public-key"); err != nil {
		panic(fmt.Sprintf("failed to mark required flag: %v", err))
	}
}

func Execute() error {
	return rootCmd.Execute()
}

func runServer(_ *cobra.Command, _ []string) {
	cfg := &config.Config{
		Port:          port,
		ServerHost:    serverHost,
		PublicKeyPath: publicKeyPath,
		Issuer:        issuer,
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	h := handlers.NewHandler(cfg)

	router.GET("/.well-known/openid-configuration", h.GetOpenIDConfiguration)
	router.GET("/keys", h.GetJWKs)

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Starting server on port %s", port)

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
		cancel()

		return
	}

	log.Println("Server exited")
}
