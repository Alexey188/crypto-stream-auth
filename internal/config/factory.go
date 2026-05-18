package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type FactoryConfig struct {
	Factory FactorySection `yaml:"factory"`
}

type FactorySection struct {
	OrgName string       `yaml:"org_name"`
	RootCA  RootCAConfig `yaml:"root_ca"`
	Camera  CameraConfig `yaml:"camera"`
}

type RootCAConfig struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}

type CameraConfig struct {
	ID            string `yaml:"id"`
	PublicKeyPath string `yaml:"public_key_path"`
	CertPath      string `yaml:"cert_path"`
}

func LoadFactory(path string) (*FactoryConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: factory config path is empty", ErrConfig)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read factory config: %w", ErrConfig, err)
	}

	var cfg FactoryConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: parse factory yaml: %w", ErrConfig, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: validate factory config: %w", ErrConfig, err)
	}

	return &cfg, nil
}

func (c *FactoryConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: factory config is nil", ErrConfig)
	}

	if c.Factory.OrgName == "" {
		return fmt.Errorf("%w: factory org name is empty", ErrConfig)
	}

	if c.Factory.RootCA.CertPath == "" {
		return fmt.Errorf("%w: root ca cert path is empty", ErrConfig)
	}

	if c.Factory.RootCA.KeyPath == "" {
		return fmt.Errorf("%w: root ca key path is empty", ErrConfig)
	}

	if c.Factory.Camera.ID == "" {
		return fmt.Errorf("%w: camera id is empty", ErrConfig)
	}

	if c.Factory.Camera.PublicKeyPath == "" {
		return fmt.Errorf("%w: camera public key path is empty", ErrConfig)
	}

	if c.Factory.Camera.CertPath == "" {
		return fmt.Errorf("%w: camera cert path is empty", ErrConfig)
	}

	return nil
}
