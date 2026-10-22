package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"panbox/internal/server"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL required")
	}
	s, err := server.Open(dsn, "", true)
	if err != nil {
		log.Fatal(err)
	}
	defer s.DB.Close()
	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Print("PANBOX Codex host worker started; waiting for ChatGPT login if required")
	s.RunCodexReviewWorker(runCtx)
}
