package config

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/gobuffalo/packr/v2"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// PolarisConfiguration contains all of the config for the validation checks.
type Config struct {
	Services Services `json:"services"`
	Configs  Configs  `json:"configs"`
	Kube     Kube     `json:"kube"`
}

// Services contains addresses of dependent services.
type Services struct {
	ScannerUrl string `json:"scannerUrl"`
}

// Configs contains names of config files
type Configs struct {
	Polaris string `json:"polaris"`
}

type Kube struct {
	NamespacesToScan []string `json:"namespaces_to_scan"`
}

func (c *Config) GetPolarisPath() (string, error) {
	if len(c.Configs.Polaris) > 0 {
		return c.Configs.Polaris, nil
	}

	dir, err := os.Getwd()
	if err != nil {
		logrus.Errorf("Error getting current working directory: %v", err)
		return "", err
	}

	path := path.Join(dir, "examples", "polaris-config.yaml")

	return path, nil
}

// NewConfig parses Scanners service config.
func NewConfig(path string) (Config, error) {
	var rawBytes []byte
	var err error
	if path == "" {
		configBox := packr.New("Config", "../../examples")
		rawBytes, err = configBox.Find("config.yaml")
	} else if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		//path is a url
		response, err2 := http.Get(path)
		if err2 != nil {
			return Config{}, err2
		}
		rawBytes, err = ioutil.ReadAll(response.Body)
	} else {
		//path is local
		rawBytes, err = ioutil.ReadFile(path)
	}
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(rawBytes)
}

// ParseConfig parses config from a byte array.
func ParseConfig(rawBytes []byte) (Config, error) {
	reader := bytes.NewReader(rawBytes)
	conf := Config{}
	d := yaml.NewYAMLOrJSONDecoder(reader, 4096)
	for {
		if err := d.Decode(&conf); err != nil {
			if err == io.EOF {
				return conf, nil
			}
			return conf, fmt.Errorf("Decoding config failed: %v", err)
		}
	}
}
