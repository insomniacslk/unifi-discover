package main

import (
	"encoding/json"
	"fmt"
	"time"

	unifidiscover "github.com/insomniacslk/unifi-discover"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

var (
	flagTimeout = pflag.DurationP("timeout", "t", 3*time.Second, "discovery timeout. A Go time string, e.g. `5s`")
	flagPort    = pflag.IntP("port", "p", 10001, "Discovery UDP destiation port")
	flagDebug   = pflag.BoolP("debug", "D", false, "Print debug logs")
	flagJSON    = pflag.BoolP("json", "j", false, "Print JSON output")
)

func main() {
	pflag.Parse()

	if *flagDebug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	target := fmt.Sprintf("255.255.255.255:%d", *flagPort)
	responses, err := unifidiscover.Discover(target, *flagTimeout)
	if err != nil {
		log.Fatalf("Discovery failed: %v", err)
	}
	if *flagJSON {
		buf, err := json.Marshal(responses)
		if err != nil {
			log.Fatalf("Failed to marshal to JSON: %v", err)
		}
		fmt.Println(string(buf))
	} else {
		for _, r := range responses {
			fmt.Println(r)
		}
	}
}
