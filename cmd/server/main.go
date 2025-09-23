package main

import (
	"fmt"
	"os"

	"github.com/bear-san/kubernetes-oidc-delegator/cmd/server/root"
)

func main() {
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
