package kube

import (
	"testing"
	"time"

	"github.com/deepnetworkgmbh/security-monitor-scanners/test"
	"github.com/stretchr/testify/assert"
)

func TestGetResourceFromAPI(t *testing.T) {
	k8s := test.SetupTestAPI()
	k8s = test.SetupAddControllers(k8s, "test")
	resources, err := CreateResourceProviderFromAPI(k8s, "test")
	assert.Equal(t, nil, err, "Error should be nil")

	assert.Equal(t, "Cluster", resources.SourceType, "Should have type Path")
	assert.Equal(t, "test", resources.SourceName, "Should have source name")
	assert.IsType(t, time.Now(), resources.CreationTime, "Creation time should be set")

	assert.Equal(t, 0, len(resources.Nodes), "Should not have any nodes")
	assert.Equal(t, 1, len(resources.Deployments), "Should have a deployment")
	assert.Equal(t, 1, len(resources.StatefulSets), "Should have a stateful set")
	assert.Equal(t, 0, len(resources.Pods), "Should have a pod")

	assert.Equal(t, "", resources.Deployments[0].ObjectMeta.Name)
}
