package main

import (
	"flag"
	"os"

	"github.com/dougbtv/whereabouts/pkg/logging"
	"github.com/dougbtv/whereabouts/pkg/reconciler"
)

func main() {
	kubeConfigFile := flag.String("kubeconfig", "", "the path to the Kubernetes configuration file")
	flag.Parse()

	if *kubeConfigFile == "" {
		_ = logging.Errorf("must specify the kubernetes config file, via the '-kubeconfig' flag")
		os.Exit(kubeconfigNotFound)
	}

	ipReconcileLoop, err := reconciler.NewReconcileLooper(*kubeConfigFile)
	if err != nil {
		os.Exit(couldNotStartOrphanedIPMonitor)
	}

	cleanedUpIps, err := ipReconcileLoop.ReconcileIPPools()
	if err != nil {
		_ = logging.Errorf("failed to clean up IP for allocations: %v", err)
	}
	logging.Debugf("successfully cleanup IPs: %+v", cleanedUpIps)
}
