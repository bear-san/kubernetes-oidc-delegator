// Package config provides configuration management for the OIDC delegator
package config

import "fmt"

type Config struct {
	Port            string
	NamespacePrefix string
	NamespaceSuffix string
	ServerHost      string
}

func (c *Config) FormatNamespace(projectID string) string {
	namespace := projectID
	if c.NamespacePrefix != "" {
		namespace = fmt.Sprintf("%s%s", c.NamespacePrefix, namespace)
	}

	if c.NamespaceSuffix != "" {
		namespace = fmt.Sprintf("%s%s", namespace, c.NamespaceSuffix)
	}

	return namespace
}
