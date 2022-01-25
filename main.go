package main

import (
	"fmt"
	"log"

	proxyserver "github.com/enercity/ed4-svc-epilot-tripica-proxy/server"
	"github.com/spf13/viper"
)

var (
	// version defines build version.
	version = "No version set during build." // nolint[gochecknoglobals]

	// buildDate defines build date.
	buildDate = "No known build date." // nolint[gochecknoglobals]

	// description defines service description.
	description = "Proxy service" // nolint[gochecknoglobals]
)

func main() {
	loadConfig()
	tripicaHost := viper.GetString("tripica.host")
	serverPort := viper.GetInt32("server.port")
	if tripicaHost == "" {
		panic("Please specify tripica's url")
	}
	serverStatus := proxyserver.NewStatus(version, buildDate, description)
	server := proxyserver.New(tripicaHost, serverStatus)

	log.Fatal(server.Run(fmt.Sprintf(":%d", serverPort)))
}

func loadConfig() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		panic("cannot read config: " + err.Error())
	}
}
