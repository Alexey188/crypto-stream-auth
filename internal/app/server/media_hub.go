package server

import (
	"context"
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/domain"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/transport"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const subscriberSendBufferSize = 4

func RequestProducerHandshake(ctx context.Context, producerAddr string, request *handshake.Request, quicConfig *quic.Config, failedCode quic.ApplicationErrorCode) (*handshake.Response, *quic.Conn, error) {
	producerConn, err := transport.Dial(ctx, producerAddr, transport.NewLocalClientTLSConfig(), quicConfig)
	if err != nil {
		return nil, nil, err
	}

	producerStream, err := transport.OpenStream(ctx, producerConn)
	if err != nil {
		_ = producerConn.CloseWithError(failedCode, "handshake failed")
		return nil, nil, err
	}

	if err := transport.WriteHandshakeRequest(producerStream, request); err != nil {
		_ = producerConn.CloseWithError(failedCode, "handshake failed")
		return nil, nil, err
	}

	response, err := transport.ReadHandshakeResponse(ctx, producerStream)
	if err != nil {
		_ = producerConn.CloseWithError(failedCode, "handshake failed")
		return nil, nil, err
	}

	return response, producerConn, nil
}

func VerifyCameraCertificate(response *handshake.Response, trustStore *authcrypto.TrustStore) error {
	if response == nil {
		return fmt.Errorf("camera certificate response is nil")
	}

	cameraCertificate, err := x509.ParseCertificate(response.CameraCertificateDER)
	if err != nil {
		return fmt.Errorf("parse camera certificate: %w", err)
	}

	if _, err := trustStore.VerifyCameraCertificate(cameraCertificate); err != nil {
		return fmt.Errorf("verify camera certificate: %w", err)
	}

	return nil
}

type FrameHub struct {
	ctx          context.Context
	cancel       context.CancelFunc
	producerConn *quic.Conn
	sessionID    [handshake.SessionIDSize]byte

	startOnce sync.Once
	stopOnce  sync.Once

	mu          sync.Mutex
	subscribers map[*consumerSubscription]struct{}
}

type consumerSubscription struct {
	streams []*quic.Stream
	frames  chan queuedFrame
	done    chan struct{}
	once    sync.Once
}

type queuedFrame struct {
	streamIndex int
	frame       *domain.VideoFrame
}

func NewFrameHub(parentCtx context.Context, producerConn *quic.Conn, sessionID [handshake.SessionIDSize]byte) *FrameHub {
	ctx, cancel := context.WithCancel(parentCtx)

	return &FrameHub{
		ctx:          ctx,
		cancel:       cancel,
		producerConn: producerConn,
		sessionID:    sessionID,
		subscribers:  make(map[*consumerSubscription]struct{}),
	}
}

func (h *FrameHub) SessionID() [handshake.SessionIDSize]byte {
	return h.sessionID
}

func (h *FrameHub) Start(onDone func(*FrameHub)) {
	h.startOnce.Do(func() {
		go func() {
			if err := h.run(); err != nil {
				log.Printf("server media hub stopped: %v", err)
			}

			h.Stop("media hub stopped")
			if onDone != nil {
				onDone(h)
			}
		}()
	})
}

func (h *FrameHub) Stop(reason string) {
	h.stopOnce.Do(func() {
		h.cancel()
		_ = h.producerConn.CloseWithError(handshakeCompletedCode, reason)
		h.closeAllSubscribers()
	})
}

func (h *FrameHub) AddConsumer(ctx context.Context, consumerConn *quic.Conn) (*consumerSubscription, error) {
	consumerStreams := make([]*quic.Stream, transport.MediaStreamCount)
	for i := range consumerStreams {
		consumerStream, err := transport.OpenStream(ctx, consumerConn)
		if err != nil {
			transport.CloseStreams(consumerStreams)
			return nil, fmt.Errorf("open consumer media stream %d: %w", i, err)
		}
		consumerStreams[i] = consumerStream
	}

	subscription := &consumerSubscription{
		streams: consumerStreams,
		frames:  make(chan queuedFrame, subscriberSendBufferSize),
		done:    make(chan struct{}),
	}

	h.mu.Lock()
	h.subscribers[subscription] = struct{}{}
	consumerCount := len(h.subscribers)
	h.mu.Unlock()

	log.Printf("consumer subscribed:\n  session_id=%s\n  consumers=%d", hex.EncodeToString(h.sessionID[:]), consumerCount)
	go h.writeConsumerFrames(subscription)
	return subscription, nil
}

func (h *FrameHub) RemoveConsumer(subscription *consumerSubscription) {
	if subscription == nil {
		return
	}

	h.mu.Lock()
	_, exists := h.subscribers[subscription]
	if exists {
		delete(h.subscribers, subscription)
	}
	consumerCount := len(h.subscribers)
	h.mu.Unlock()

	subscription.Close()

	if !exists {
		return
	}

	log.Printf("consumer unsubscribed:\n  session_id=%s\n  consumers=%d", hex.EncodeToString(h.sessionID[:]), consumerCount)
	if consumerCount == 0 {
		h.Stop("no consumers")
	}
}

func (subscription *consumerSubscription) Wait(ctx context.Context) error {
	select {
	case <-subscription.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (subscription *consumerSubscription) Close() {
	subscription.once.Do(func() {
		transport.CloseStreams(subscription.streams)
		close(subscription.done)
	})
}

func (h *FrameHub) writeConsumerFrames(subscription *consumerSubscription) {
	for {
		select {
		case item := <-subscription.frames:
			if item.streamIndex >= len(subscription.streams) {
				h.RemoveConsumer(subscription)
				return
			}
			if err := transport.WriteFrame(subscription.streams[item.streamIndex], item.frame); err != nil {
				log.Printf("drop consumer:\n  reason=%v", err)
				h.RemoveConsumer(subscription)
				return
			}
		case <-subscription.done:
			return
		case <-h.ctx.Done():
			return
		}
	}
}

func (h *FrameHub) run() error {
	producerStreams := make([]*quic.Stream, transport.MediaStreamCount)
	for i := range producerStreams {
		producerStream, err := transport.AcceptStream(h.ctx, h.producerConn)
		if err != nil {
			return fmt.Errorf("accept producer media stream %d: %w", i, err)
		}
		producerStreams[i] = producerStream
	}
	defer transport.CloseStreams(producerStreams)

	statsWindowStarted := time.Now()
	var statsFrames uint64
	var statsPayloadBytes uint64

	for result := range transport.ReadFramesFromStreams(h.ctx, producerStreams) {
		if result.Err != nil {
			if errors.Is(result.Err, io.EOF) || transport.IsGracefulRemoteClose(result.Err) {
				log.Printf("producer media stream finished")
				return nil
			}
			if h.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read producer frame from media stream %d: %w", result.StreamIndex, result.Err)
		}

		h.broadcast(result)

		statsFrames++
		statsPayloadBytes += uint64(len(result.Frame.Payload))

		now := time.Now()
		if now.Sub(statsWindowStarted) >= time.Second {
			elapsed := now.Sub(statsWindowStarted).Seconds()
			avgPayload := uint64(0)
			if statsFrames > 0 {
				avgPayload = statsPayloadBytes / statsFrames
			}
			log.Printf("server relay stats: frames=%d bytes=%d fps=%.1f avg_payload=%d consumers=%d",
				statsFrames,
				statsPayloadBytes,
				float64(statsFrames)/elapsed,
				avgPayload,
				h.ConsumerCount(),
			)

			statsWindowStarted = now
			statsFrames = 0
			statsPayloadBytes = 0
		}
	}

	return nil
}

func (h *FrameHub) broadcast(result transport.FrameReadResult) {
	h.mu.Lock()
	subscribers := make([]*consumerSubscription, 0, len(h.subscribers))
	for subscription := range h.subscribers {
		subscribers = append(subscribers, subscription)
	}
	h.mu.Unlock()

	for _, subscription := range subscribers {
		subscription.Enqueue(result.StreamIndex, result.Frame)
	}
}

func (subscription *consumerSubscription) Enqueue(streamIndex int, frame *domain.VideoFrame) {
	item := queuedFrame{
		streamIndex: streamIndex,
		frame:       frame,
	}

	select {
	case subscription.frames <- item:
		return
	default:
	}

	select {
	case <-subscription.frames:
	default:
	}

	select {
	case subscription.frames <- item:
	default:
	}
}

func (h *FrameHub) ConsumerCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}

func (h *FrameHub) closeAllSubscribers() {
	h.mu.Lock()
	subscribers := make([]*consumerSubscription, 0, len(h.subscribers))
	for subscription := range h.subscribers {
		subscribers = append(subscribers, subscription)
		delete(h.subscribers, subscription)
	}
	h.mu.Unlock()

	for _, subscription := range subscribers {
		subscription.Close()
	}
}
