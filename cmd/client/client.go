package main

import (
	"github.com/rbicker/godra-cli-client/handler"
	"log"
	"os"
	"os/signal"
	"strconv"
)

func main() {
	var opts []func(*handler.Handler) error
	clientId := os.Getenv("CLIENT_ID")
	if clientId == "" {
		log.Fatal("CLIENT_ID environment variable is undefined")
	}
	hydraURL := "http://localhost:4444"
	if v, ok := os.LookupEnv("HYDRA_URL"); ok {
		hydraURL = v
	}
	if v, ok := os.LookupEnv("PORT"); ok {
		p, err := strconv.Atoi(v)
		if err != nil {
			log.Fatalf("error: given port %s is not a valid number", v)
		}
		opts = append(opts, handler.SetPort(p))
	}
	h, err := handler.NewHandler(hydraURL, clientId, opts...)
	if err != nil {
		log.Fatal("error creating login handler")
	}
	log.Println("press control+c to cancel login")
	go func() {
		var c chan os.Signal
		c = make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		h.Cancel()
	}()
	err = h.RunHydraAuthCodeFlow()
	if err != nil {
		log.Fatalf("error while performing login: %s", err)
	}
	log.Println("access token:", h.AccessToken())
	err = h.Logout()
	if err != nil {
		log.Fatalf("error while logging out: %s", err)
	}
	log.Println("logged out", h.AccessToken(), h.IDToken())
}
