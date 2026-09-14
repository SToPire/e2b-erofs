//go:build linux

package sandbox

import (
	"maps"
	"slices"

	"google.golang.org/protobuf/proto"
)

// Clone gives a fresh lifecycle its own configuration. The prior execution's
// teardown still reads its configuration after checkpoint starts restoring the
// replacement, which normalizes memory settings and envd defaults.
func (c *Config) Clone() *Config {
	if c.mu != nil {
		c.mu.RLock()
		defer c.mu.RUnlock()
	}
	copy := *c
	copy.Network = proto.CloneOf(c.Network)
	copy.Envd.Vars = maps.Clone(c.Envd.Vars)
	copy.Envd.DefaultUser = cloneConfigString(c.Envd.DefaultUser)
	copy.Envd.DefaultWorkdir = cloneConfigString(c.Envd.DefaultWorkdir)
	copy.Envd.AccessToken = cloneConfigString(c.Envd.AccessToken)
	copy.VolumeMounts = slices.Clone(c.VolumeMounts)
	return NewConfig(copy)
}

func cloneConfigString(value *string) *string {
	if value == nil {
		return nil
	}
	return new(*value)
}
