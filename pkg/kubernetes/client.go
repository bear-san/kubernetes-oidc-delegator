// Package kubernetes provides Kubernetes API client functionality
package kubernetes

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

type Client struct {
	client client.Client
}

func NewClient() (*Client, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	cl, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return &Client{
		client: cl,
	}, nil
}

func (c *Client) GetServiceAccountSecret(ctx context.Context, namespace, clusterName string) (*corev1.Secret, error) {
	secretName := fmt.Sprintf("%s-sa", clusterName)

	secret := &corev1.Secret{}
	key := types.NamespacedName{
		Namespace: namespace,
		Name:      secretName,
	}

	if err := c.client.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	return secret, nil
}
