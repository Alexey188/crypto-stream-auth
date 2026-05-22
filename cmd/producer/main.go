package main

import (
	"context"
	"crypto-stream-auth/internal/app/producer"
	"crypto-stream-auth/internal/media"
	"crypto-stream-auth/internal/tpm"
	"log"
	"time"
)

const (
	listenAddr     = "127.0.0.1:4242"
	cameraCertPath = "artifacts/certs/camera.crt"

	handshakeTimeout = 5 * time.Second
	idleTimeout      = 30 * time.Second
)

func main() {
	prod, err := producer.New(producer.Options{
		ListenAddr:       listenAddr,
		CameraCertPath:   cameraCertPath,
		CameraKeyHandle:  tpm.DefaultCameraKeyHandle,
		HandshakeTimeout: handshakeTimeout,
		IdleTimeout:      idleTimeout,
		MediaSource: media.FFmpegSourceConfig{
			Width:  640,
			Height: 360,
			FPS:    30,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer prod.Close()

	if err := prod.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
