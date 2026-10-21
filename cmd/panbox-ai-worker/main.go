package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"panbox/internal/server"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := server.CheckCodexChatGPTLogin(ctx); err != nil {
		log.Fatal(err)
	}
	cancel()
	s, err := server.Open(dsn, "", true)
	if err != nil {
		log.Fatal(err)
	}
	defer s.DB.Close()
	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Print("PANBOX Codex host worker started")
	s.RunCodexReviewWorker(runCtx)
}
