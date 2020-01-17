package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	conf "github.com/deepnetworkgmbh/security-monitor-scanners/pkg/config"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/service"
	"github.com/gorilla/handlers"
	"github.com/sirupsen/logrus"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Required for other auth providers like GKE.
)

const (
	// Version represents the current release version of Scanners
	Version = "0.2.0"
)

func main() {
	// Load CLI Flags
	port := flag.Int("port", 8080, "Port for the Scanners webserver")
	serviceBasePath := flag.String("service-base-path", "/", "Path on which the Scanners are served")
	config := flag.String("config", "", "Location of Scanners configuration file")
	logLevel := flag.String("log-level", logrus.InfoLevel.String(), "Logrus log level")
	version := flag.Bool("version", false, "Prints the version of Scanners")

	flag.Parse()

	if *version {
		fmt.Printf("Scanners version %s\n", Version)
		os.Exit(0)
	}

	parsedLevel, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Errorf("log-level flag has invalid value %s", *logLevel)
	} else {
		logrus.SetLevel(parsedLevel)
	}

	c, err := conf.NewConfig(*config)
	if err != nil {
		logrus.Errorf("Error parsing config at %s: %v", *config, err)
		os.Exit(1)
	}

	startScannersServer(&c, *port, *serviceBasePath)
}

func startScannersServer(c *conf.Config, port int, basePath string) {
	handler := service.NewHandler(c, port, basePath)

	corsObj := []handlers.CORSOption{
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
	}

	srv := &http.Server{
		Handler: handlers.CORS(corsObj...)(handler.GetRouter()),
		Addr:    fmt.Sprintf(":%d", port),
	}

	logrus.Infof("Starting Scanners server on port %d", port)
	logrus.Fatal(srv.ListenAndServe())
}
