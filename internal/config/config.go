// Package config provides configuration management for the OIDC delegator
package config

type Config struct {
	Port          string
	ServerHost    string
	PublicKeyPath string
	Issuer        string
}
