package cmd

import (
	"flag"
	"fmt"
	"log/slog"

	pflag "github.com/spf13/pflag"
)

type LevelFlag slog.Level

func (l *LevelFlag) Set(value string) error {
	switch value {
	case "debug":
		*l = LevelFlag(slog.LevelDebug)
	case "info":
		*l = LevelFlag(slog.LevelInfo)
	case "warn":
		*l = LevelFlag(slog.LevelWarn)
	case "error":
		*l = LevelFlag(slog.LevelError)
	default:
		return fmt.Errorf("unknown log level: %s", value)
	}
	return nil
}

func (l *LevelFlag) String() string {
	switch slog.Level(*l) {
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return "info"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	default:
		return ""
	}
}

func (l *LevelFlag) Get() interface{} {
	return slog.Level(*l)
}

func (l *LevelFlag) Type() string {
	return "string"
}

var _lf = LevelFlag(slog.LevelInfo)
var _ flag.Getter = &_lf
var _ pflag.Value = &_lf
