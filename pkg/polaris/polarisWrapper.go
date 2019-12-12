package polaris

import (
	"fmt"
	scannersConfig "github.com/deepnetworkgmbh/security-monitor-scanners/pkg/config"
	polarisConfig "github.com/fairwindsops/polaris/pkg/config"
	"github.com/fairwindsops/polaris/pkg/kube"
	"github.com/fairwindsops/polaris/pkg/validator"
	"github.com/sirupsen/logrus"
	"math/rand"
	"time"
)

// RequestAudit asynchronously requests a new audit and stores the result associated with returned id
func RequestAudit(scannersCfg *scannersConfig.Config) string {
	// I assume, that probability of requesting audit at the same second is small enough,
	// that "salting" it with rand-1024 value is enough to avoid overlaps
	requestId := fmt.Sprintf("%d-%d", time.Now().Unix(), rand.Intn(1024))

	// TODO: persist the result with associated requestId
	go AuditKubeCluster(scannersCfg)

	return requestId
}

// GetAuditResultById returns audit associated with request identifier
func GetAuditResultById(scannersCfg *scannersConfig.Config, requestId string) (*validator.AuditData, error) {
	// TODO: query audit result from a storage
	return AuditKubeCluster(scannersCfg)
}

// AuditKubeCluster performs cluster audit
func AuditKubeCluster(scannersCfg *scannersConfig.Config) (*validator.AuditData, error) {
	path, err := scannersCfg.GetPolarisPath()
	if err != nil {
		logrus.Errorf("Error getting Polaris config %v", err)
		return nil, err
	}

	c, err := polarisConfig.ParseFile(path)
	if err != nil {
		logrus.Errorf("Error parsing config at %s: %v", scannersCfg.Configs.Polaris, err)
	}

	k, err := kube.CreateResourceProviderFromCluster()
	if err != nil {
		logrus.Errorf("Error fetching Kubernetes resources %v", err)
		return nil, err
	}

	filterByNamespace(k, scannersCfg.Kube.NamespacesToScan...)
	auditData, err := validator.RunAudit(c, k)
	if err != nil {
		logrus.Errorf("Error getting audit data: %v", err)
		return nil, err
	}

	return &auditData, err
}