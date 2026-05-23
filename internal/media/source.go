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

type FFplaySink struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser

	closeOnce sync.Once
	closeErr  error
}

type FFmpegSourceConfig struct {
	FFmpegPath     string
	Width          int
	Height         int
	FPS            int
	MaxPayloadSize int
}

type FFmpegSource struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	reader *PayloadReader

	closeOnce sync.Once
	closeErr  error
}

type PayloadReader struct {
	reader io.Reader
	buffer []byte
}

func NewFFmpegSource(ctx context.Context, cfg FFmpegSourceConfig) (*FFmpegSource, error) {
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

	return &FFmpegSource{
		cmd:    cmd,
		stdout: stdout,
		reader: NewPayloadReader(stdout, cfg.MaxPayloadSize),
	}, nil
}

func (s *FFmpegSource) NextPayload(ctx context.Context) ([]byte, error) {
	if s == nil || s.reader == nil {
		return nil, fmt.Errorf("%w: ffmpeg source is nil", ErrMedia)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("%w: read payload cancelled: %w", ErrMedia, err)
	}

	payload, err := s.reader.NextPayload()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: read payload cancelled: %w", ErrMedia, ctxErr)
		}
		return nil, fmt.Errorf("%w: read payload: %w", ErrMedia, err)
	}

	return payload, nil
}

func (s *FFmpegSource) Close() error {
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

func NewPayloadReader(reader io.Reader, maxPayloadSize int) *PayloadReader {
	if maxPayloadSize <= 0 {
		maxPayloadSize = domain.MaxFramePayloadSize
	}

	return &PayloadReader{
		reader: reader,
		buffer: make([]byte, maxPayloadSize),
	}
}

func (r *PayloadReader) NextPayload() ([]byte, error) {
	if r == nil || r.reader == nil {
		return nil, fmt.Errorf("%w: payload reader is nil", ErrMedia)
	}

	n, err := r.reader.Read(r.buffer)
	if n > 0 {
		return r.buffer[:n], nil
	}
	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("%w: empty payload read", ErrMedia)
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
		return fmt.Errorf("%w: payload is empty", ErrMedia)
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

func normalizeFFmpegConfig(cfg FFmpegSourceConfig) FFmpegSourceConfig {
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

func ffmpegArgs(cfg FFmpegSourceConfig) []string {
	size := strconv.Itoa(cfg.Width) + "x" + strconv.Itoa(cfg.Height)
	rate := strconv.Itoa(cfg.FPS)
	x264Params := "bframes=0:rc-lookahead=0:sync-lookahead=0:keyint=" + rate + ":scenecut=0:repeat-headers=1"

	return []string{
		"-hide_banner",
		"-loglevel", "error",
		"-fflags", "nobuffer",
		"-flags", "low_delay",
		"-probesize", "32",
		"-analyzeduration", "0",
		"-f", "dshow",
		"-framerate", rate,
		"-video_size", size,
		"-i", "video=HD User Facing",
		"-an",
		"-c:v", "libx264",
		"-preset", "ultrafast",
		"-tune", "zerolatency",
		"-pix_fmt", "yuv420p",
		"-x264-params", x264Params,
		"-flush_packets", "1",
		"-muxdelay", "0",
		"-muxpreload", "0",
		"-f", "mpegts",
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
		"-sync", "ext",
		"-analyzeduration", "100000",
		"-probesize", "4096",
		"-f", "mpegts",
		"-i", "pipe:0",
	}
}
