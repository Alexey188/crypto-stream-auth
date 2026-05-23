package main

import (
	"context"
	"crypto-stream-auth/internal/app/producer"
	"crypto-stream-auth/internal/media"
	"log"
)

const (
	listenAddr     = "127.0.0.1:4242"
	cameraCertPath = "artifacts/camera/camera2.crt"
)

func main() {
	prod, err := producer.New(producer.Options{
		ListenAddr:     listenAddr,
		CameraCertPath: cameraCertPath,
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
