//go:build linux

package cfg

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/willscott/go-nfs"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
)

const DefaultBusyboxVersion = "1.36.1"

type BuilderConfig struct {
	// EROFSSnapshotDir enables local EROFS builds and restores. It must be on
	// persistent local storage, outside the disposable template/build caches.
	EROFSSnapshotDir          string `env:"EROFS_SNAPSHOT_DIR"`
	EROFSNativeMemoryVerified bool   `env:"EROFS_NATIVE_MEMORY_VERIFIED" envDefault:"false"`
	EROFSMkfsPath             string `env:"EROFS_MKFS_PATH" envDefault:"mkfs.erofs"`
	DomainName                string `env:"DOMAIN_NAME"              envDefault:""`
	FirecrackerVersionsDir    string `env:"FIRECRACKER_VERSIONS_DIR" envDefault:"/fc-versions"`
	BusyboxVersion            string `env:"BUSYBOX_VERSION"          envDefault:"1.36.1"`
	HostBusyboxDir            string `env:"HOST_BUSYBOX_DIR"         envDefault:"/fc-busybox"`
	HostEnvdPath              string `env:"HOST_ENVD_PATH"           envDefault:"/fc-envd/envd"`
	HostKernelsDir            string `env:"HOST_KERNELS_DIR"         envDefault:"/fc-kernels"`
	OrchestratorBaseDir       string `env:"ORCHESTRATOR_BASE_PATH"   envDefault:"/orchestrator"`
	SandboxDir                string `env:"SANDBOX_DIR"              envDefault:"/fc-vm"`
	SharedChunkCacheDir       string `env:"SHARED_CHUNK_CACHE_PATH"`
	TemplatesDir              string `env:"TEMPLATES_DIR,expand"     envDefault:"${ORCHESTRATOR_BASE_PATH}/build-templates"`

	DefaultCacheDir string `env:"DEFAULT_CACHE_DIR,expand" envDefault:"${ORCHESTRATOR_BASE_PATH}/build"`

	Provider string `env:"PROVIDER" envDefault:"gcp"`

	StorageConfig storage.Config
	NetworkConfig network.Config
}

func makePathsAbsolute(c *BuilderConfig) error {
	for _, item := range []*string{
		&c.EROFSSnapshotDir,
		&c.DefaultCacheDir,
		&c.FirecrackerVersionsDir,
		&c.HostBusyboxDir,
		&c.HostEnvdPath,
		&c.HostKernelsDir,
		&c.OrchestratorBaseDir,
		&c.StorageConfig.SandboxCacheDir,
		&c.SandboxDir,
		&c.SharedChunkCacheDir,
		&c.StorageConfig.TemplateCacheDir,
		&c.TemplatesDir,
	} {
		dir := *item

		if dir == "" {
			continue
		}

		if filepath.IsAbs(dir) {
			continue
		}

		dir, err := filepath.Abs(dir)
		if err != nil {
			return fmt.Errorf("failed to resolve %q to absolute path: %w", *item, err)
		}

		*item = dir
	}

	if c.EROFSSnapshotDir != "" {
		if !c.EROFSNativeMemoryVerified {
			return fmt.Errorf("EROFS_SNAPSHOT_DIR requires EROFS_NATIVE_MEMORY_VERIFIED after testing the deployed Firecracker binary")
		}
		canonical, err := canonicalConfigPath(c.EROFSSnapshotDir)
		if err != nil {
			return err
		}
		c.EROFSSnapshotDir = canonical
		for _, disposable := range []string{c.DefaultCacheDir, c.StorageConfig.SandboxCacheDir, c.StorageConfig.TemplateCacheDir, c.TemplatesDir, c.SandboxDir} {
			if disposable == "" {
				continue
			}
			disposable, err := canonicalConfigPath(disposable)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(disposable, c.EROFSSnapshotDir)
			if err != nil {
				return err
			}
			if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
				return fmt.Errorf("EROFS_SNAPSHOT_DIR must be outside disposable or namespace-covered directory %q", disposable)
			}
		}
	}

	return nil
}

// Resolve existing ancestors too, since a store may not have been created yet.
// This prevents a symlink alias from hiding a store underneath a cache cleanup
// or the tmpfs mounted over SandboxDir in Firecracker's private namespace.
func canonicalConfigPath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		// Reconstructing this name under its resolved parent would preserve an
		// unresolved alias and bypass the containment check. Missing ordinary
		// directories are allowed, but configured symlinks must resolve now.
		return "", fmt.Errorf("configuration path %q contains a dangling symlink: %w", path, err)
	}
	if statErr != nil && !os.IsNotExist(statErr) {
		return "", statErr
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	resolved, err = canonicalConfigPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}

type Config struct {
	BuilderConfig

	ClickhouseConnectionString  string            `env:"CLICKHOUSE_CONNECTION_STRING"`
	ClickhouseConnectionStrings []string          `env:"CLICKHOUSE_CONNECTION_STRINGS" envSeparator:";"`
	DisableStartupReclaim       bool              `env:"DISABLE_STARTUP_RECLAIM"`
	ForceStop                   bool              `env:"FORCE_STOP"`
	GRPCPort                    uint16            `env:"GRPC_PORT"                     envDefault:"5008"`
	InstanceGroupName           string            `env:"INSTANCE_GROUP_NAME"`
	LocalUploadBaseURL          string            `env:"LOCAL_UPLOAD_BASE_URL"`
	NodeIP                      string            `env:"NODE_IP"                       envDefault:"localhost"`
	NodeLabels                  []string          `env:"NODE_LABELS"                   envSeparator:","`
	OrchestratorLockPath        string            `env:"ORCHESTRATOR_LOCK_PATH"        envDefault:"/orchestrator.lock"`
	NFSProxyLogging             bool              `env:"NFS_PROXY_LOGGING"             envDefault:"false"`
	NFSProxyTracing             bool              `env:"NFS_PROXY_TRACING"             envDefault:"false"`
	NFSProxyMetrics             bool              `env:"NFS_PROXY_METRICS"             envDefault:"true"`
	NFSProxyRecordHandleCalls   bool              `env:"NFS_PROXY_RECORD_HANDLE_CALLS" envDefault:"false"`
	NFSProxyRecordStatCalls     bool              `env:"NFS_PROXY_RECORD_STAT_CALLS"   envDefault:"false"`
	NFSProxyLogLevel            nfs.LogLevel      `env:"NFS_PROXY_LOG_LEVEL"           envDefault:"info"`
	ProxyPort                   uint16            `env:"PROXY_PORT"                    envDefault:"5007"`
	RedisClusterURL             string            `env:"REDIS_CLUSTER_URL"`
	RedisTLSCABase64            string            `env:"REDIS_TLS_CA_BASE64"`
	RedisTLSEnabled             bool              `env:"REDIS_TLS_ENABLED"`
	RedisPassword               string            `env:"REDIS_PASSWORD"`
	RedisURL                    string            `env:"REDIS_URL"`
	RedisPoolSize               int               `env:"REDIS_POOL_SIZE"               envDefault:"5"`
	RedisMinIdleConns           int               `env:"REDIS_MIN_IDLE_CONNS"          envDefault:"2"`
	NBDPoolSize                 int               `env:"NBD_POOL_SIZE"                 envDefault:"64"`
	Services                    []string          `env:"ORCHESTRATOR_SERVICES"         envDefault:"orchestrator"`
	PersistentVolumeMounts      map[string]string `env:"PERSISTENT_VOLUME_MOUNTS"`
}

// AdditionalClickhouseEndpoints returns the non-blank entries from
// CLICKHOUSE_CONNECTION_STRINGS that are *in addition to* the singular
// CLICKHOUSE_CONNECTION_STRING. Order is preserved; first occurrence wins on
// dedup. Returns nil endpoints if nothing remains.
func (c Config) AdditionalClickhouseEndpoints() (endpoints, droppedDuplicates []string) {
	singular := strings.TrimSpace(c.ClickhouseConnectionString)
	seen := make(map[string]struct{}, len(c.ClickhouseConnectionStrings))
	if singular != "" {
		seen[singular] = struct{}{}
	}

	for _, raw := range c.ClickhouseConnectionStrings {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			droppedDuplicates = append(droppedDuplicates, s)

			continue
		}
		seen[s] = struct{}{}
		endpoints = append(endpoints, s)
	}

	return endpoints, droppedDuplicates
}

func (c Config) NodeAddress() *string {
	if c.NodeIP == "localhost" {
		return nil
	}

	addr := net.JoinHostPort(c.NodeIP, strconv.FormatUint(uint64(c.GRPCPort), 10))

	return &addr
}

func Parse() (Config, error) {
	config, err := env.ParseAsWithOptions[Config](env.Options{
		FuncMap: map[reflect.Type]env.ParserFunc{
			reflect.TypeFor[nfs.LogLevel](): func(s string) (any, error) {
				s = strings.ToLower(s)

				return nfs.Log.ParseLevel(s)
			},
		},
	})
	if err != nil {
		return config, err
	}

	bc := config.BuilderConfig
	if err = makePathsAbsolute(&bc); err != nil {
		return config, err
	}

	config.BuilderConfig = bc

	if err = config.BuilderConfig.NetworkConfig.Validate(); err != nil {
		return config, err
	}

	if config.PersistentVolumeMounts != nil {
		for name, path := range config.PersistentVolumeMounts {
			path = filepath.Clean(path)
			path, err = filepath.Abs(path)
			if err != nil {
				return config, fmt.Errorf("failed to make persistent volume mount %q an absolute path: %w", name, err)
			}

			if _, err := os.Stat(path); err != nil {
				return config, fmt.Errorf("failed to access persistent volume mount %q (%q): %w", name, path, err)
			}

			config.PersistentVolumeMounts[name] = path // store the cleaned path
		}
	}

	return config, nil
}

func ParseBuilder() (BuilderConfig, error) {
	model, err := env.ParseAs[BuilderConfig]()
	if err != nil {
		return BuilderConfig{}, err
	}

	if err = makePathsAbsolute(&model); err != nil {
		return BuilderConfig{}, err
	}

	if err = model.NetworkConfig.Validate(); err != nil {
		return BuilderConfig{}, err
	}

	return model, nil
}
