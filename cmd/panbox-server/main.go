package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"panbox/internal/server"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL required")
	}
	webDir := os.Getenv("PANBOX_WEB_DIR")
	if webDir == "" {
		webDir = "web/dist"
	}
	s, err := server.Open(dsn, webDir, os.Getenv("PANBOX_SECURE_COOKIE") != "false")
	if err != nil {
		log.Fatal(err)
	}
	defer s.DB.Close()
	addr := os.Getenv("PANBOX_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	h := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("PANBOX listening on %s", addr)
	log.Fatal(h.ListenAndServe())
}
