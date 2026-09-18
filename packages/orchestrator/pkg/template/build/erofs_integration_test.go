//go:build linux

package build

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
	"github.com/launchdarkly/go-sdk-common/v3/ldvalue"
	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/e2b-dev/infra/packages/clickhouse/pkg/hoststats"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/proxy"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox"
	blockmetrics "github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block/metrics"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/cgroup"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/fc"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/nbd"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
	sbxtemplate "github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/template"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/template/peerclient"
	buildconfig "github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/config"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/metrics"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/sandboxtools"
	buildpaths "github.com/e2b-dev/infra/packages/orchestrator/pkg/template/build/storage/paths"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
	artifactsregistry "github.com/e2b-dev/infra/packages/shared/pkg/artifacts-registry"
	"github.com/e2b-dev/infra/packages/shared/pkg/dockerhub"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
	templatemanager "github.com/e2b-dev/infra/packages/shared/pkg/grpc/template-manager"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
	sbxlogger "github.com/e2b-dev/infra/packages/shared/pkg/logger/sandbox"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
	"github.com/e2b-dev/infra/packages/shared/pkg/templates"
)

// TestEROFSBuilderOCI exercises actual OCI extraction, the injected provisioning
// script, real systemd/envd boot, USER/RUN and finalize through Builder.Build.
// It never substitutes the provisioning script, init system, or guest agent.
// E2B_EROFS_BUILDER_IMAGE names a local Docker image; the supplied Dockerfile
// installs the real Debian prerequisites to avoid external guest networking.
func TestEROFSBuilderOCI(t *testing.T) { //nolint:paralleltest // Privileged VM fixtures and process-global logger/PATH.
	imageName := os.Getenv("E2B_EROFS_BUILDER_IMAGE")
	if imageName == "" {
		t.Skip("set E2B_EROFS_BUILDER_IMAGE and native VM tool paths")
	}
	require.Zero(t, os.Geteuid())
	pmemMode := os.Getenv("E2B_PMEM_BUILDER") == "1"
	agentTemplate := os.Getenv("E2B_PMEM_AGENT_TEMPLATE") == "1"
	memoryMB := int64(512)
	if agentTemplate {
		require.True(t, pmemMode)
		memoryMB = 2048
	}
	if pmemMode {
		_, err := os.Stat("/sys/module/nbd")
		require.ErrorIs(t, err, os.ErrNotExist, "NBD must be absent")
	}
	inputs := make(map[string]string)
	for _, key := range []string{"FC", "KERNEL", "MKFS", "FSCK", "ENVD", "BUSYBOX_DIR", "TEST_DIR"} {
		inputs[key] = os.Getenv("E2B_EROFS_" + key)
		require.NotEmpty(t, inputs[key], key)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Minute)
	defer cancel()
	work, err := os.MkdirTemp(inputs["TEST_DIR"], "builder-")
	require.NoError(t, err)
	t.Logf("retained real Builder artifacts: %s", work)
	var successReport map[string]any
	t.Cleanup(func() {
		if t.Failed() || successReport == nil {
			return
		}
		report, err := json.MarshalIndent(successReport, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(work, "report.json"), append(report, '\n'), 0o644))
	})
	logfile, err := os.Create(filepath.Join(work, "build.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logfile.Close()) })
	core := zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), zapcore.AddSync(logfile), zap.DebugLevel)
	log := logger.NewTracedLoggerFromCore(core)
	logger.ReplaceGlobals(ctx, log)
	sbxlogger.SetSandboxLoggerInternal(log)
	sbxlogger.SetSandboxLoggerExternal(log)
	// Serve a real OCI image on an ephemeral localhost registry. Builder then
	// pulls it through its regular public-image path, without cloud writes.
	registryDir := filepath.Join(work, "registry")
	require.NoError(t, os.MkdirAll(registryDir, 0o755))
	reg := httptest.NewServer(registry.New(registry.WithBlobHandler(registry.NewDiskBlobHandler(registryDir))))
	t.Cleanup(reg.Close)
	localRef, err := name.ParseReference(imageName)
	require.NoError(t, err)
	image, err := daemon.Image(localRef, daemon.WithContext(ctx))
	require.NoError(t, err)
	ref, err := name.ParseReference(strings.TrimPrefix(reg.URL, "http://")+"/erofs/builder:base", name.Insecure)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, image, remote.WithContext(ctx)))
	imageDigest, err := image.Digest()
	require.NoError(t, err)
	versions := fc.Config{KernelVersion: "6.1.155", FirecrackerVersion: "v1.14-0.1.0", NativeMemory: true}
	if version := os.Getenv("E2B_EROFS_FC_VERSION"); version != "" {
		versions.FirecrackerVersion = version
	}
	if version := os.Getenv("E2B_EROFS_KERNEL_VERSION"); version != "" {
		versions.KernelVersion = version
	}
	config := cfg.Config{BuilderConfig: cfg.BuilderConfig{
		EROFSSnapshotDir: filepath.Join(work, "snapshots"), EROFSNativeMemoryVerified: true, EROFSMkfsPath: inputs["MKFS"],
		DefaultCacheDir: filepath.Join(work, "diff-cache"), SharedChunkCacheDir: filepath.Join(work, "chunks"), TemplatesDir: filepath.Join(work, "templates"),
		FirecrackerVersionsDir: filepath.Join(work, "firecracker"), HostKernelsDir: filepath.Join(work, "kernels"),
		HostEnvdPath: inputs["ENVD"], HostBusyboxDir: inputs["BUSYBOX_DIR"], BusyboxVersion: cfg.DefaultBusyboxVersion,
		OrchestratorBaseDir: filepath.Join(work, "orchestrator"), SandboxDir: filepath.Join(work, "fc-vm"),
		StorageConfig: storage.Config{SandboxCacheDir: filepath.Join(work, "sandbox-cache"), TemplateCacheDir: filepath.Join(work, "template-cache")},
	}}
	if pmemMode {
		config.EROFSNativeOnly, config.EROFSPmemVerified = true, true
		config.EROFSPmemInitramfsPath = os.Getenv("E2B_PMEM_INITRD")
		require.NotEmpty(t, config.EROFSPmemInitramfsPath)
	}
	for _, path := range []string{config.EROFSSnapshotDir, config.DefaultCacheDir, config.TemplatesDir, config.StorageConfig.SandboxCacheDir, config.StorageConfig.TemplateCacheDir,
		filepath.Join(config.FirecrackerVersionsDir, versions.FirecrackerVersion), filepath.Join(config.HostKernelsDir, versions.KernelVersion), filepath.Join(work, "bin")} {
		require.NoError(t, os.MkdirAll(path, 0o755))
	}
	require.NoError(t, os.Symlink(inputs["FC"], filepath.Join(config.FirecrackerVersionsDir, versions.FirecrackerVersion, "firecracker")))
	require.NoError(t, os.Symlink(inputs["KERNEL"], filepath.Join(config.HostKernelsDir, versions.KernelVersion, "vmlinux.bin")))
	require.NoError(t, os.Symlink(inputs["FSCK"], filepath.Join(work, "bin", "fsck.erofs")))
	t.Setenv("PATH", filepath.Join(work, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	datasource := ldtestdata.DataSource()
	datasource.Update(datasource.Flag(featureflags.FirecrackerVersions.Key()).ValueForAll(ldvalue.FromJSONMarshal(map[string]string{})))
	flags, err := featureflags.NewClientWithDatasource(datasource)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, flags.Close(context.WithoutCancel(ctx))) })
	meter := noop.NewMeterProvider()
	blockMetrics, err := blockmetrics.NewMetrics(meter)
	require.NoError(t, err)
	storageTemplate, err := storage.NewProvider(ctx, storage.Spec{Provider: storage.LocalStorageProvider, BasePath: filepath.Join(work, "storage-template")})
	require.NoError(t, err)
	storageBuild, err := storage.NewProvider(ctx, storage.Spec{Provider: storage.LocalStorageProvider, BasePath: filepath.Join(work, "storage-build")})
	require.NoError(t, err)
	cache, err := sbxtemplate.NewCache(config, flags, storageTemplate, blockMetrics, peerclient.NopResolver())
	require.NoError(t, err)
	cache.Start(ctx)
	t.Cleanup(cache.Stop)
	var devices *nbd.DevicePool
	if !pmemMode {
		devices, err = nbd.NewDevicePool(2)
		require.NoError(t, err)
		poolCtx, cancelPool := context.WithCancel(context.WithoutCancel(ctx))
		go devices.Populate(poolCtx)
		t.Cleanup(func() { cancelPool(); require.NoError(t, devices.Close(context.WithoutCancel(ctx))) })
	}
	netPool := &builderEROFSNetworkPool{slots: make(map[string]*network.Slot), hostAccess: true}
	t.Cleanup(func() { require.NoError(t, netPool.Close(context.WithoutCancel(ctx))) })
	sandboxes := sandbox.NewSandboxesMap()
	var factory *sandbox.Factory
	if pmemMode {
		factory, err = sandbox.NewFileFactory(ctx, config.BuilderConfig, netPool, flags, hoststats.NewNoopDelivery(), cgroup.NewNoopManager(), network.NewNoopEgressProxy(), nil, sandboxes)
		require.NoError(t, err)
	} else {
		factory = sandbox.NewFactory(ctx, config.BuilderConfig, netPool, devices, flags, hoststats.NewNoopDelivery(), cgroup.NewNoopManager(), network.NewNoopEgressProxy(), nil, sandboxes)
	}
	t.Cleanup(func() { require.NoError(t, factory.CloseSharedMounts(context.Background())) })
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := portListener.Addr().(*net.TCPAddr).Port
	require.NoError(t, portListener.Close())
	sbxProxy, err := proxy.NewSandboxProxy(meter, uint16(port), sandboxes, flags)
	require.NoError(t, err)
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- sbxProxy.Start(ctx) }()
	t.Cleanup(func() {
		require.NoError(t, sbxProxy.Close(context.WithoutCancel(ctx)))
		err := <-proxyDone
		if !errors.Is(err, http.ErrServerClosed) {
			require.NoError(t, err)
		}
	})
	artifacts, err := artifactsregistry.NewLocalArtifactsRegistry()
	require.NoError(t, err)
	dockerRepo := dockerhub.NewNoopRemoteRepository()
	t.Cleanup(func() { require.NoError(t, dockerRepo.Close()) })
	buildMetrics, err := metrics.NewBuildMetrics(meter)
	require.NoError(t, err)
	uploads := sandbox.NewUploads(cache, storageTemplate, peerclient.NopResolver(), nil)
	t.Cleanup(uploads.Stop)
	builder := NewBuilder(config.BuilderConfig, log, flags, factory, storageTemplate, storageBuild, artifacts, dockerRepo, sbxProxy, sandboxes, cache, buildMetrics, uploads)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		for _, sbx := range sandboxes.LifecycleItems() {
			if err := sbx.Close(cleanupCtx); err != nil {
				t.Errorf("close sandbox: %v", err)
			}
		}
	})
	buildID, templateID := uuid.NewString(), "erofs-builder-test"
	force := true
	buildConfig := buildconfig.TemplateConfig{Version: templates.TemplateV2LatestVersion, TeamID: uuid.NewString(), TemplateID: templateID, CacheScope: uuid.NewString(),
		FromImage: ref.Name(), Force: &force, VCpuCount: 2, MemoryMB: memoryMB, DiskSizeMB: 512, FreeDiskSizeMB: 256,
		HugePages: true, FreePageReporting: true, FreePageHinting: true, KernelVersion: versions.KernelVersion, FirecrackerVersion: versions.FirecrackerVersion,
		Steps:    []*templatemanager.TemplateStep{{Type: "RUN", Args: []string{"printf 'real-oci-erofs-builder\\n' > /opt/erofs-build-marker; sync", "root"}}},
		ReadyCmd: "test \"$(cat /opt/erofs-build-marker)\" = real-oci-erofs-builder",
	}
	if agentTemplate {
		setup := "id user >/dev/null 2>&1 || useradd -m -s /bin/bash user; chown -R root:root /testbed; cd /testbed; test \"$(git rev-parse HEAD)\" = 514579c655bf22e2af14f0743376ae1d7befe345; /opt/miniconda3/envs/testbed/bin/python -m pip install --no-deps --no-build-isolation -e .; /opt/miniconda3/envs/testbed/bin/python -c 'import sympy; print(sympy.__version__)'; claude --version; chown -R user:user /testbed"
		buildConfig.Steps = append(buildConfig.Steps, &templatemanager.TemplateStep{Type: "RUN", Args: []string{"set -eu; " + setup, "root"}})
	}
	if pmemMode {
		var archive bytes.Buffer
		gz := gzip.NewWriter(&archive)
		tw := tar.NewWriter(gz)
		payload := []byte("real-copy-input\n")
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: "copied.txt", Mode: 0644, Size: int64(len(payload))}))
		_, err := tw.Write(payload)
		require.NoError(t, err)
		require.NoError(t, tw.Close())
		require.NoError(t, gz.Close())
		hash := fmt.Sprintf("%x", sha256.Sum256(archive.Bytes()))
		blob, err := storageBuild.OpenBlob(ctx, buildpaths.GetLayerFilesCachePath(buildConfig.CacheScope, hash))
		require.NoError(t, err)
		require.NoError(t, blob.Put(ctx, archive.Bytes()))
		buildConfig.Steps = append(buildConfig.Steps, &templatemanager.TemplateStep{Type: "COPY", Args: []string{"copied.txt", "/usr/local/bin/erofs-copy-marker", "root", "0644"}, FilesHash: &hash})
		buildConfig.ReadyCmd += " && test \"$(cat /usr/local/bin/erofs-copy-marker)\" = real-copy-input"
	}
	result, err := builder.Build(ctx, storage.Paths{BuildID: buildID}, buildConfig, core)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, versions.KernelVersion, result.KernelVersion)
	require.Equal(t, versions.FirecrackerVersion, result.FirecrackerVersion)
	store, err := erofs.NewStore(config.EROFSSnapshotDir, erofs.Options{MkfsPath: inputs["MKFS"], FsckPath: inputs["FSCK"]})
	require.NoError(t, err)
	final, err := store.Load(buildID)
	require.NoError(t, err)
	require.Equal(t, memoryMB<<20, final.Manifest.Memory.Size)
	require.Equal(t, result.RootfsSizeMB<<20, final.Manifest.WritableDisk().Size)
	require.Positive(t, result.RootfsSizeMB)
	if pmemMode {
		require.Equal(t, erofs.LayoutPmem, final.Manifest.Boot.Layout)
		require.Equal(t, "full", final.Manifest.MemoryCapture)
		require.Empty(t, final.Manifest.ParentID)
	}
	meta, err := metadata.FromFile(final.MetadataPath())
	require.NoError(t, err)
	require.Equal(t, buildID, meta.Template.BuildID)
	require.Nil(t, meta.Prefetch)
	require.False(t, meta.IsFilesystemOnly())
	tmpl, err := cache.GetTemplate(ctx, buildID, false, false)
	require.NoError(t, err)
	runtime := sandbox.RuntimeMetadata{SandboxID: "t" + uuid.NewString()[:8], ExecutionID: uuid.NewString(), TemplateID: templateID, TeamID: buildConfig.TeamID, BuildID: buildID, SandboxType: sandbox.SandboxTypeBuild}
	sbx, err := factory.ResumeSandbox(ctx, tmpl, sandbox.NewConfig(sandbox.Config{Vcpu: 2, RamMB: memoryMB, FirecrackerConfig: versions, Envd: sandbox.EnvdMetadata{Version: result.EnvdVersion}}), runtime, time.Now(), time.Now().Add(time.Hour), nil)
	require.NoError(t, err)
	defer sbx.Close(context.WithoutCancel(ctx))
	var stdout strings.Builder
	verify := "set -eu; test \"$(cat /opt/erofs-build-marker)\" = real-oci-erofs-builder; test \"$(cat /proc/1/comm)\" = systemd; systemctl is-active --quiet envd; . /usr/local/share/e2b/distro.env; test \"$E2B_INIT_SYSTEM\" = systemd; id user; grep -q 'BUILD_ID=" + buildID + "' /.e2b; echo EROFS-BUILDER-PASS"
	require.NoError(t, sandboxtools.RunCommandWithOutput(ctx, sbxProxy, runtime.SandboxID, verify, metadata.Context{User: "root"}, func(out, _ string) { stdout.WriteString(out) }))
	require.Contains(t, stdout.String(), "EROFS-BUILDER-PASS")
	if pmemMode {
		require.NoError(t, sandboxtools.RunCommandWithOutput(ctx, sbxProxy, runtime.SandboxID, "test -f /.e2b-rootfs/lower/usr/local/bin/erofs-copy-marker && test ! -e /.e2b-rootfs/upperfs/upper/usr/local/bin/erofs-copy-marker", metadata.Context{User: "root"}, func(string, string) {}))
	}

	require.NoError(t, sbx.Close(ctx))
	if pmemMode && !agentTemplate {
		// Repeat the same recipe with cached intermediate layers. Finalization
		// still creates a fresh upper with the configured root reservation.
		cachedConfig := buildConfig
		noForce := false
		cachedConfig.Force = &noForce
		cachedID := uuid.NewString()
		cachedResult, err := builder.Build(ctx, storage.Paths{BuildID: cachedID}, cachedConfig, core)
		require.NoError(t, err)
		cachedSnapshot, err := store.Load(cachedID)
		require.NoError(t, err)
		require.Equal(t, cachedResult.RootfsSizeMB<<20, cachedSnapshot.Manifest.WritableDisk().Size)
		// A derived build reads the complete merged parent, including RUN/COPY
		// results, then creates a different lower through the Guest export helper.
		derived := buildConfig
		derived.FromImage = ""
		derived.FromTemplate = &templatemanager.FromTemplateConfig{Alias: "pmem-parent", BuildID: buildID}
		derived.Steps = []*templatemanager.TemplateStep{{Type: "RUN", Args: []string{"test \"$(cat /usr/local/bin/erofs-copy-marker)\" = real-copy-input; rm /usr/local/bin/erofs-copy-marker; printf derived > /opt/derived-marker; sync", "root"}}}
		derived.ReadyCmd = "test \"$(cat /opt/derived-marker)\" = derived && test ! -e /usr/local/bin/erofs-copy-marker"
		derivedID := uuid.NewString()
		derivedResult, err := builder.Build(ctx, storage.Paths{BuildID: derivedID}, derived, core)
		require.NoError(t, err)
		derivedSnapshot, err := store.Load(derivedID)
		require.NoError(t, err)
		require.NotEqual(t, final.Manifest.Lower.ID, derivedSnapshot.Manifest.Lower.ID)
		require.Empty(t, derivedSnapshot.Manifest.ParentID)
		require.Equal(t, "full", derivedSnapshot.Manifest.MemoryCapture)
		childTemplate, err := cache.GetTemplate(ctx, derivedID, false, false)
		require.NoError(t, err)
		childRuntime := runtime
		childRuntime.SandboxID = "t" + uuid.NewString()[:8]
		childRuntime.ExecutionID = uuid.NewString()
		childRuntime.BuildID = derivedID
		child, err := factory.ResumeSandbox(ctx, childTemplate, sandbox.NewConfig(sandbox.Config{Vcpu: 2, RamMB: memoryMB, FirecrackerConfig: versions, Envd: sandbox.EnvdMetadata{Version: derivedResult.EnvdVersion}}), childRuntime, time.Now(), time.Now().Add(time.Hour), nil)
		require.NoError(t, err)
		defer child.Close(context.WithoutCancel(ctx))
		require.NoError(t, sandboxtools.RunCommandWithOutput(ctx, sbxProxy, childRuntime.SandboxID, derived.ReadyCmd+" && grep -q BUILD_ID="+derivedID+" /.e2b", metadata.Context{User: "root"}, func(string, string) {}))
		require.NoError(t, child.Close(ctx))
		_, err = os.Stat("/sys/module/nbd")
		require.ErrorIs(t, err, os.ErrNotExist)
		t.Logf("pmem Builder cached rebuild %s and FROM-template %s passed", cachedID, derivedID)
	}
	logData, err := os.ReadFile(filepath.Join(work, "build.log"))
	require.NoError(t, err)
	require.Contains(t, string(logData), "Provisioning was successful")
	successReport = map[string]any{"status": "passed", "oci_digest": imageDigest.String(), "build_id": buildID, "envd_version": result.EnvdVersion, "firecracker_sha256": builderEROFSHash(t, inputs["FC"]), "initial_oci": true, "real_provisioning": true, "real_systemd": true, "run_step": true, "finalize": true, "final_file_restore": true}
	successReport["native_only"], successReport["agent_template"], successReport["memory_mb"] = pmemMode, agentTemplate, memoryMB
	successReport["store_root"], successReport["kernel_version"], successReport["firecracker_version"] = config.EROFSSnapshotDir, versions.KernelVersion, versions.FirecrackerVersion
	if pmemMode {
		successReport["lower_id"] = final.Manifest.Lower.ID
	}

	t.Log("Builder.Build OCI -> provisioning -> systemd/envd -> USER/RUN -> finalize -> EROFS File restore passed")
}

func builderEROFSHash(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// A real tap and netns, optionally with a veth route for host envd requests.
// Firewall rules stay inside the namespace; the Factory acquires/releases real
// Slot values through its normal pool API.
type builderEROFSNetworkPool struct {
	mu         sync.Mutex
	slots      map[string]*network.Slot
	hostAccess bool
	closed     bool
}

func (p *builderEROFSNetworkPool) Get(ctx context.Context, _ *orchestrator.SandboxNetworkConfig, _ network.EgressClass) (*network.Slot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("lifecycle network pool is closed")
	}
	for idx := 20000 + os.Getpid()%8000; idx < 32767; idx++ {
		slot, err := network.NewSlot("erofs-lifecycle-"+strconv.Itoa(idx), idx, network.Config{}, network.NewNoopEgressProxy())
		if err != nil {
			return nil, err
		}
		if out, err := exec.CommandContext(ctx, "ip", "netns", "add", slot.NamespaceID()).CombinedOutput(); err != nil {
			if _, statErr := os.Stat(filepath.Join("/var/run/netns", slot.NamespaceID())); statErr == nil {
				continue
			}
			return nil, fmt.Errorf("create test netns: %w: %s", err, out)
		}
		p.slots[slot.NamespaceID()] = slot
		commands := [][]string{
			{"-n", slot.NamespaceID(), "tuntap", "add", "dev", slot.TapName(), "mode", "tap"},
			// Match the stable host tap MAC used by the production pool so the
			// guest's restored ARP cache stays valid across fresh namespaces.
			{"-n", slot.NamespaceID(), "link", "set", "dev", slot.TapName(), "address", "02:fc:00:00:00:06"},
			{"-n", slot.NamespaceID(), "address", "add", slot.TapIPString() + "/30", "dev", slot.TapName()},
			{"-n", slot.NamespaceID(), "link", "set", "dev", slot.TapName(), "up"},
			{"-n", slot.NamespaceID(), "link", "set", "lo", "up"},
		}
		if p.hostAccess {
			host, peer := "ev"+strconv.Itoa(idx), "ep"+strconv.Itoa(idx)
			commands = append(commands,
				[]string{"link", "add", host, "type", "veth", "peer", "name", peer, "netns", slot.NamespaceID()},
				[]string{"address", "add", slot.VethIP().String() + "/31", "dev", host},
				[]string{"link", "set", host, "up"},
				[]string{"-n", slot.NamespaceID(), "address", "add", slot.VpeerIP().String() + "/31", "dev", peer},
				[]string{"-n", slot.NamespaceID(), "link", "set", peer, "up"},
				[]string{"route", "add", slot.HostCIDR(), "via", slot.VpeerIP().String(), "dev", host},
				[]string{"netns", "exec", slot.NamespaceID(), "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"},
				[]string{"netns", "exec", slot.NamespaceID(), "iptables", "-t", "nat", "-A", "PREROUTING", "-d", slot.HostIPString(), "-j", "DNAT", "--to-destination", slot.NamespaceIP()},
				[]string{"netns", "exec", slot.NamespaceID(), "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", slot.TapName(), "-j", "SNAT", "--to-source", slot.TapIPString()},
			)
		}
		for _, args := range commands {
			if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
				return nil, fmt.Errorf("configure test tap: %w: %s", err, out)
			}
		}
		return slot, nil
	}
	return nil, errors.New("no unused test network namespace")
}

func (p *builderEROFSNetworkPool) ReturnAsync(ctx context.Context, slot *network.Slot, released network.ReleaseNotify, _ time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.slots[slot.NamespaceID()]; !ok {
		return nil
	}
	if out, err := exec.CommandContext(ctx, "ip", "netns", "delete", slot.NamespaceID()).CombinedOutput(); err != nil {
		return fmt.Errorf("delete test netns: %w: %s", err, out)
	}
	delete(p.slots, slot.NamespaceID())
	if released != nil {
		released(ctx, slot.HostIPString())
	}
	return nil
}

func (p *builderEROFSNetworkPool) Close(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	slots := make([]*network.Slot, 0, len(p.slots))
	for _, slot := range p.slots {
		slots = append(slots, slot)
	}
	p.mu.Unlock()
	var result error
	for _, slot := range slots {
		result = errors.Join(result, p.ReturnAsync(ctx, slot, nil, 0))
	}
	return result
}
