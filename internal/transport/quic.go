package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"time"

	"crypto-stream-auth/internal/handshake"

	quic "github.com/quic-go/quic-go"
)

var ErrTransport = errors.New("transport")

const (
	ALPN             = "crypto-stream-auth/1"
	MediaStreamCount = 1

	lengthFieldSize    = 2
	timestampFieldSize = 8

	maxHandshakeRequestSize  = 1 + handshake.NonceSize
	maxHandshakeResponseSize = 1 +
		lengthFieldSize + handshake.MaxCertificateDERSize +
		ed25519.PublicKeySize +
		handshake.SessionIDSize +
		handshake.NonceSize +
		timestampFieldSize +
		lengthFieldSize + handshake.RSAPSSSignatureSize
)

func Listen(addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Listener, error) {
	tlsConfig, err := prepareTLSConfig(tlsConfig)
	if err != nil {
		return nil, err
	}

	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: listen: %w", ErrTransport, err)
	}

	return listener, nil
}

func Dial(ctx context.Context, addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	tlsConfig, err := prepareTLSConfig(tlsConfig)
	if err != nil {
		return nil, err
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: dial: %w", ErrTransport, err)
	}

	return conn, nil
}

func NewQUICConfig(handshakeTimeout time.Duration, idleTimeout time.Duration) *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		MaxIdleTimeout:       idleTimeout,
		MaxIncomingStreams:   2,
	}
}

func AcceptConnection(ctx context.Context, listener *quic.Listener) (*quic.Conn, error) {
	if listener == nil {
		return nil, fmt.Errorf("%w: listener is nil", ErrTransport)
	}

	conn, err := listener.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: accept connection: %w", ErrTransport, err)
	}

	return conn, nil
}

func CloseSession(conn *quic.Conn, handlerErr *error, failedCode quic.ApplicationErrorCode, completedCode quic.ApplicationErrorCode) {
	code := failedCode
	reason := "handshake failed"
	if handlerErr != nil && *handlerErr == nil {
		code = completedCode
		reason = "session complete"
	}

	closeErr := conn.CloseWithError(code, reason)
	if handlerErr != nil && *handlerErr == nil && closeErr != nil {
		*handlerErr = closeErr
	}
}

func IsGracefulRemoteClose(err error) bool {
	var appErr *quic.ApplicationError
	return errors.As(err, &appErr) && appErr.Remote && appErr.ErrorCode == 0
}

func OpenStream(ctx context.Context, conn *quic.Conn) (*quic.Stream, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: connection is nil", ErrTransport)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: open stream: %w", ErrTransport, err)
	}

	return stream, nil
}

func AcceptStream(ctx context.Context, conn *quic.Conn) (*quic.Stream, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: connection is nil", ErrTransport)
	}

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: accept stream: %w", ErrTransport, err)
	}

	return stream, nil
}

func CloseStreams(streams []*quic.Stream) {
	for _, stream := range streams {
		if stream != nil {
			_ = stream.Close()
		}
	}
}

func WriteHandshakeRequest(stream *quic.Stream, request *handshake.Request) error {
	data, err := handshake.EncodeRequest(request)
	if err != nil {
		return fmt.Errorf("%w: encode handshake request: %w", ErrTransport, err)
	}

	return writeMessage(stream, data)
}

func ReadHandshakeRequest(ctx context.Context, stream *quic.Stream) (*handshake.Request, error) {
	data, err := readMessage(ctx, stream, maxHandshakeRequestSize)
	if err != nil {
		return nil, fmt.Errorf("%w: read handshake request: %w", ErrTransport, err)
	}

	request, err := handshake.DecodeRequest(data)
	if err != nil {
		return nil, fmt.Errorf("%w: decode handshake request: %w", ErrTransport, err)
	}

	return request, nil
}

func WriteHandshakeResponse(stream *quic.Stream, response *handshake.Response) error {
	data, err := handshake.EncodeResponse(response)
	if err != nil {
		return fmt.Errorf("%w: encode handshake response: %w", ErrTransport, err)
	}

	return writeMessage(stream, data)
}

func ReadHandshakeResponse(ctx context.Context, stream *quic.Stream) (*handshake.Response, error) {
	data, err := readMessage(ctx, stream, maxHandshakeResponseSize)
	if err != nil {
		return nil, fmt.Errorf("%w: read handshake response: %w", ErrTransport, err)
	}

	response, err := handshake.DecodeResponse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: decode handshake response: %w", ErrTransport, err)
	}

	return response, nil
}

func prepareTLSConfig(tlsConfig *tls.Config) (*tls.Config, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("%w: tls config is nil", ErrTransport)
	}

	cloned := tlsConfig.Clone()
	if len(cloned.NextProtos) == 0 {
		cloned.NextProtos = []string{ALPN}
	}

	return cloned, nil
}

func writeMessage(stream *quic.Stream, data []byte) error {
	if stream == nil {
		return fmt.Errorf("%w: stream is nil", ErrTransport)
	}

	for len(data) > 0 {
		n, err := stream.Write(data)
		if err != nil {
			return fmt.Errorf("%w: write stream: %w", ErrTransport, err)
		}
		if n == 0 {
			return fmt.Errorf("%w: write stream: %w", ErrTransport, io.ErrShortWrite)
		}
		data = data[n:]
	}

	if err := stream.Close(); err != nil {
		return fmt.Errorf("%w: close stream write side: %w", ErrTransport, err)
	}

	return nil
}

func readMessage(ctx context.Context, stream *quic.Stream, maxSize int) ([]byte, error) {
	if stream == nil {
		return nil, fmt.Errorf("%w: stream is nil", ErrTransport)
	}
	if maxSize <= 0 {
		return nil, fmt.Errorf("%w: max message size is invalid", ErrTransport)
	}

	result := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(stream, int64(maxSize+1)))
		result <- readResult{data: data, err: err}
	}()

	select {
	case <-ctx.Done():
		stream.CancelRead(0)
		return nil, fmt.Errorf("%w: read cancelled: %w", ErrTransport, ctx.Err())
	case result := <-result:
		if result.err != nil {
			return nil, fmt.Errorf("%w: read stream: %w", ErrTransport, result.err)
		}
		if len(result.data) > maxSize {
			return nil, fmt.Errorf("%w: message is too large", ErrTransport)
		}
		return result.data, nil
	}
}

type readResult struct {
	data []byte
	err  error
}
