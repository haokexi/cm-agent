package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is intentionally small and maps 1:1 to flags/env vars used by the demo.
// This keeps the "demo startup" friction low while enabling stable deployments.
type Config struct {
	Log struct {
		Level string `yaml:"level"`
	} `yaml:"log"`

	Scrape struct {
		Interval Duration `yaml:"interval"`
	} `yaml:"scrape"`

	Collectors struct {
		DisableDefaults bool     `yaml:"disable_defaults"`
		Filters         []string `yaml:"filters"`
	} `yaml:"collectors"`

	Labels struct {
		Job      string            `yaml:"job"`
		Instance string            `yaml:"instance"`
		Extra    map[string]string `yaml:"extra"`
	} `yaml:"labels"`

	RemoteWrite struct {
		URL                 string   `yaml:"url"`
		BearerToken         string   `yaml:"bearer_token"`
		Timeout             Duration `yaml:"timeout"`
		MaxSeriesPerRequest int      `yaml:"max_series_per_request"`

		Spool struct {
			Dir      string `yaml:"dir"`
			MaxBytes int64  `yaml:"max_bytes"`
			MaxFiles int    `yaml:"max_files"`
		} `yaml:"spool"`

		Flush struct {
			MaxFiles int `yaml:"max_files"`
		} `yaml:"flush"`
	} `yaml:"remote_write"`
}

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(v *yaml.Node) error {
	switch v.Kind {
	case yaml.ScalarNode:
		if v.Value == "" {
			d.Duration = 0
			return nil
		}
		dd, err := time.ParseDuration(v.Value)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", v.Value, err)
		}
		d.Duration = dd
		return nil
	default:
		return errors.New("duration must be a string (e.g. \"15s\")")
	}
}

func Load(path string) (*Config, error) {
	if path == "" {
		return &Config{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
