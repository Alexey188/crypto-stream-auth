package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

var ErrConfig = errors.New("config")

type Config struct {
	Handshake   HandshakeConfig   `yaml:"handshake"`
	Stream      StreamConfig      `yaml:"stream"`
	FramePolicy FramePolicyConfig `yaml:"frame_policy"`
	QUIC        QUICConfig        `yaml:"quic"`
}

type HandshakeConfig struct {
	MaxAge time.Duration `yaml:"max_age"`
}

type StreamConfig struct {
	MaxFrameAge time.Duration `yaml:"max_frame_age"`
}
type FramePolicyConfig struct {
	WindowDuration time.Duration `yaml:"window_duration"`
	MinFrames      int           `yaml:"min_frames"`
	MaxBadRatio    float64       `yaml:"max_bad_ratio"`
}

type QUICConfig struct {
}

// дополнять
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: config path is empty", ErrConfig)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read config: %w", ErrConfig, err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: parse config yaml: %w", ErrConfig, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: validate config: %w", ErrConfig, err)
	}

	return &cfg, nil
}

// дополнять
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: config is nil", ErrConfig)
	}

	if c.Handshake.MaxAge <= 0 {
		return fmt.Errorf("%w: handshake max age must be positive", ErrConfig)
	}

	if c.Stream.MaxFrameAge <= 0 {
		return fmt.Errorf("%w: stream max frame age must be positive", ErrConfig)
	}

	if c.FramePolicy.WindowDuration <= 0 {
		return fmt.Errorf("%w: frame policy window duration must be positive", ErrConfig)
	}

	if c.FramePolicy.MinFrames <= 0 {
		return fmt.Errorf("%w: frame policy min frames must be positive", ErrConfig)
	}

	if c.FramePolicy.MaxBadRatio <= 0 || c.FramePolicy.MaxBadRatio >= 1 {
		return fmt.Errorf("%w: frame policy max bad ratio must be between 0 and 1", ErrConfig)
	}
	return nil
}
