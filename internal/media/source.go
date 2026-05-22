package media

import (
	"context"
	"crypto-stream-auth/internal/domain"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"
)

var ErrMedia = errors.New("media")

type Source interface {
	NextPayload(ctx context.Context) ([]byte, error)
	Close() error
}

type FFplaySink struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser

	closeOnce sync.Once
	closeErr  error
}

type FFmpegH264SourceConfig struct {
	FFmpegPath     string
	Width          int
	Height         int
	FPS            int
	MaxPayloadSize int
}

type FFmpegH264Source struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	reader *PayloadReader

	closeOnce sync.Once
	closeErr  error
}

func NewFFmpegH264Source(ctx context.Context, cfg FFmpegH264SourceConfig) (*FFmpegH264Source, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	cfg = normalizeFFmpegConfig(cfg)

	cmd := exec.CommandContext(ctx, cfg.FFmpegPath, ffmpegArgs(cfg)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: open ffmpeg stdout: %w", ErrMedia, err)
	}
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: start ffmpeg: %w", ErrMedia, err)
	}

	return &FFmpegH264Source{
		cmd:    cmd,
		stdout: stdout,
		reader: NewPayloadReader(stdout, cfg.MaxPayloadSize),
	}, nil
}

func (s *FFmpegH264Source) NextPayload(ctx context.Context) ([]byte, error) {
	if s == nil || s.reader == nil {
		return nil, fmt.Errorf("%w: ffmpeg source is nil", ErrMedia)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	result := make(chan payloadResult, 1)
	go func() {
		payload, err := s.reader.NextPayload()
		result <- payloadResult{payload: payload, err: err}
	}()

	select {
	case <-ctx.Done():
		_ = s.Close()
		return nil, fmt.Errorf("%w: read payload cancelled: %w", ErrMedia, ctx.Err())
	case result := <-result:
		if result.err != nil {
			return nil, fmt.Errorf("%w: read payload: %w", ErrMedia, result.err)
		}
		return result.payload, nil
	}
}

func (s *FFmpegH264Source) Close() error {
	if s == nil {
		return nil
	}

	s.closeOnce.Do(func() {
		if s.stdout != nil {
			s.closeErr = s.stdout.Close()
		}
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
			_ = s.cmd.Wait()
		}
	})

	if s.closeErr != nil {
		return fmt.Errorf("%w: close ffmpeg source: %w", ErrMedia, s.closeErr)
	}
	return nil
}

func NewFFplaySink(ctx context.Context, ffplayPath string) (*FFplaySink, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ffplayPath == "" {
		ffplayPath = "ffplay"
	}

	cmd := exec.CommandContext(ctx, ffplayPath, ffplayArgs()...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: open ffplay stdin: %w", ErrMedia, err)
	}
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: start ffplay: %w", ErrMedia, err)
	}

	return &FFplaySink{
		cmd:   cmd,
		stdin: stdin,
	}, nil
}

func (s *FFplaySink) WritePayload(payload []byte) error {
	if s == nil || s.stdin == nil {
		return fmt.Errorf("%w: ffplay sink is nil", ErrMedia)
	}
	if len(payload) == 0 {
		return fmt.Errorf("%w: h264 payload is empty", ErrMedia)
	}
	if _, err := s.stdin.Write(payload); err != nil {
		return fmt.Errorf("%w: write ffplay payload: %w", ErrMedia, err)
	}
	return nil
}

func (s *FFplaySink) Close() error {
	if s == nil {
		return nil
	}

	s.closeOnce.Do(func() {
		if s.stdin != nil {
			s.closeErr = s.stdin.Close()
			s.stdin = nil
		}
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
			_ = s.cmd.Wait()
		}
	})

	if s.closeErr != nil {
		return fmt.Errorf("%w: close ffplay sink: %w", ErrMedia, s.closeErr)
	}
	return nil
}

type payloadResult struct {
	payload []byte
	err     error
}

func normalizeFFmpegConfig(cfg FFmpegH264SourceConfig) FFmpegH264SourceConfig {
	if cfg.FFmpegPath == "" {
		cfg.FFmpegPath = "ffmpeg"
	}
	if cfg.Width <= 0 {
		cfg.Width = 640
	}
	if cfg.Height <= 0 {
		cfg.Height = 360
	}
	if cfg.FPS <= 0 {
		cfg.FPS = 30
	}
	if cfg.MaxPayloadSize <= 0 {
		cfg.MaxPayloadSize = domain.MaxFramePayloadSize
	}
	return cfg
}

func ffmpegArgs(cfg FFmpegH264SourceConfig) []string {
	//size := strconv.Itoa(cfg.Width) + "x" + strconv.Itoa(cfg.Height)
	rate := strconv.Itoa(cfg.FPS)

	return []string{
		"-hide_banner",
		"-loglevel", "error",
		"-re",
		"-f", "dshow",
		"-i", "video=HD User Facing",
		"-an",
		"-c:v", "libx264",
		"-preset", "ultrafast",
		"-tune", "zerolatency",
		"-pix_fmt", "yuv420p",
		"-x264-params", "keyint=" + rate + ":scenecut=0",
		"-f", "h264",
		"pipe:1",
	}
}

func ffplayArgs() []string {
	return []string{
		"-hide_banner",
		"-loglevel", "error",
		"-fflags", "nobuffer",
		"-flags", "low_delay",
		"-framedrop",
		"-analyzeduration", "0",
		"-probesize", "32",
		"-f", "h264",
		"-i", "pipe:0",
	}
}
