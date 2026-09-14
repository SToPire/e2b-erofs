//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/launchdarkly/go-sdk-common/v3/ldvalue"
	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/e2b-dev/infra/packages/clickhouse/pkg/hoststats"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	eventservice "github.com/e2b-dev/infra/packages/orchestrator/pkg/events"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/proxy"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox"
	blockmetrics "github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block/metrics"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/cgroup"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/erofs"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/nbd"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/template"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/template/peerclient"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/service"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/template/metadata"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
	"github.com/e2b-dev/infra/packages/shared/pkg/telemetry"
)

// TestEROFSCheckpointGRPCLifecycle uses the real SandboxService over gRPC and
// real Firecracker/envd/qcow2/EROFS. Its seed is generation zero from a passing
// TestEROFSFactoryLifecycle envd run, named by E2B_EROFS_BASELINE_FACTORY_DIR.
// The original namespace-visible SandboxDir is retained for vmstate paths;
// all new generations and runtime files are isolated in a fresh test directory.
func TestEROFSCheckpointGRPCLifecycle(t *testing.T) { //nolint:paralleltest // Owns privileged kernel resources and fixture PATH.
	baselineFactory := os.Getenv("E2B_EROFS_BASELINE_FACTORY_DIR")
	if baselineFactory == "" {
		t.Skip("set E2B_EROFS_BASELINE_FACTORY_DIR to a passing real-envd Factory fixture")
	}
	require.Zero(t, os.Geteuid())
	inputs := make(map[string]string)
	for _, key := range []string{"FC", "KERNEL", "MKFS", "FSCK", "ENVD", "TEST_DIR"} {
		inputs[key] = os.Getenv("E2B_EROFS_" + key)
		require.NotEmpty(t, inputs[key], "missing E2B_EROFS_"+key)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	var provenance map[string]any
	data, err := os.ReadFile(filepath.Join(baselineFactory, "report.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &provenance))
	require.Equal(t, true, provenance["envd_enabled"])
	require.Equal(t, "passed", provenance["status"])
	require.Equal(t, provenance["firecracker_sha256"], serverEROFSHash(t, inputs["FC"]))
	require.Equal(t, provenance["envd_sha256"], serverEROFSHash(t, inputs["ENVD"]))
	work, err := os.MkdirTemp(inputs["TEST_DIR"], "grpc-")
	require.NoError(t, err)
	t.Logf("retained gRPC lifecycle artifacts: %s", work)
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		report, err := json.MarshalIndent(map[string]any{"status": "passed", "baseline_factory": baselineFactory,
			"firecracker_sha256": provenance["firecracker_sha256"], "envd_sha256": provenance["envd_sha256"],
			"grpc_checkpoint_flag_false": true, "grpc_checkpoint_flag_true": true, "committed_error_roundtrip": true,
			"post_commit_resume_retry": true, "filesystem_only_pause_preserves_live_vm": true,
			"checkpoint_status_phases": true, "checkpoint_receipt_reload": true, "capture_failure_pending": true}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(work, "report.json"), append(report, '\n'), 0o644))
	})
	source, err := erofs.NewStore(filepath.Join(baselineFactory, "snapshots"), erofs.Options{})
	require.NoError(t, err)
	entries, err := os.ReadDir(source.Root)
	require.NoError(t, err)
	var baseline *erofs.Snapshot
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		candidate, err := source.Load(entry.Name())
		require.NoError(t, err)
		if candidate.Manifest.ParentID == "" {
			require.Nil(t, baseline)
			baseline = candidate
		}
	}
	require.NotNil(t, baseline)
	meta, err := metadata.FromFile(baseline.MetadataPath())
	require.NoError(t, err)
	config := cfg.Config{BuilderConfig: cfg.BuilderConfig{
		EROFSSnapshotDir: filepath.Join(work, "snapshots"), EROFSNativeMemoryVerified: true, EROFSMkfsPath: inputs["MKFS"],
		DefaultCacheDir: filepath.Join(work, "diff-cache"), SharedChunkCacheDir: filepath.Join(work, "chunks"),
		FirecrackerVersionsDir: filepath.Join(work, "firecracker"), HostKernelsDir: filepath.Join(work, "kernels"),
		OrchestratorBaseDir: filepath.Join(work, "orchestrator"), SandboxDir: filepath.Join(baselineFactory, "fc-vm"),
		StorageConfig: storage.Config{SandboxCacheDir: filepath.Join(work, "sandbox-cache"), TemplateCacheDir: filepath.Join(work, "template-cache")},
	}}
	for _, path := range []string{config.EROFSSnapshotDir, config.DefaultCacheDir, config.StorageConfig.SandboxCacheDir, config.StorageConfig.TemplateCacheDir,
		filepath.Join(config.FirecrackerVersionsDir, meta.Template.FirecrackerVersion), filepath.Join(config.HostKernelsDir, meta.Template.KernelVersion), filepath.Join(work, "bin")} {
		require.NoError(t, os.MkdirAll(path, 0o755))
	}
	serverEROFSCommand(t, ctx, "cp", "-a", baseline.Dir, filepath.Join(config.EROFSSnapshotDir, baseline.Manifest.ID))
	require.NoError(t, os.Symlink(inputs["FC"], filepath.Join(config.FirecrackerVersionsDir, meta.Template.FirecrackerVersion, "firecracker")))
	require.NoError(t, os.Symlink(inputs["KERNEL"], filepath.Join(config.HostKernelsDir, meta.Template.KernelVersion, "vmlinux.bin")))
	require.NoError(t, os.Symlink(inputs["FSCK"], filepath.Join(work, "bin", "fsck.erofs")))
	blockMkfs, enteredMkfs, failMkfs := filepath.Join(work, "block-mkfs"), filepath.Join(work, "entered-mkfs"), filepath.Join(work, "fail-mkfs")
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	config.EROFSMkfsPath = filepath.Join(work, "bin", "mkfs-wrapper")
	require.NoError(t, os.WriteFile(config.EROFSMkfsPath, []byte("#!/bin/sh\nif [ -e "+quote(failMkfs)+" ]; then exit 77; fi\n"+
		"if [ -e "+quote(blockMkfs)+" ]; then touch "+quote(enteredMkfs)+"; while [ -e "+quote(blockMkfs)+" ]; do sleep 0.02; done; fi\n"+
		"exec "+quote(inputs["MKFS"])+" \"$@\"\n"), 0o755))
	t.Cleanup(func() { _ = os.Remove(blockMkfs) })
	t.Setenv("PATH", filepath.Join(work, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	envdVersion := strings.TrimSpace(string(serverEROFSCommand(t, ctx, inputs["ENVD"], "-version")))
	store, err := erofs.NewStore(config.EROFSSnapshotDir, erofs.Options{MkfsPath: inputs["MKFS"], FsckPath: inputs["FSCK"]})
	require.NoError(t, err)
	datasource := ldtestdata.DataSource()
	// This fixture is pinned to the binary whose digest passed native RAM
	// validation; do not apply the deployment's default release remapping.
	datasource.Update(datasource.Flag(featureflags.FirecrackerVersions.Key()).ValueForAll(ldvalue.FromJSONMarshal(map[string]string{})))
	flags, err := featureflags.NewClientWithDatasource(datasource)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, flags.Close(context.WithoutCancel(ctx))) })
	meter := noop.NewMeterProvider()
	metrics, err := blockmetrics.NewMetrics(meter)
	require.NoError(t, err)
	// Any unexpected object-store access is an immediate mock failure. Native
	// snapshots must resolve exclusively through the configured local store.
	persistence := storage.NewMockStorageProvider(t)
	cache, err := template.NewCache(config, flags, persistence, metrics, peerclient.NopResolver())
	require.NoError(t, err)
	cache.Start(ctx)
	t.Cleanup(cache.Stop)
	devices, err := nbd.NewDevicePool(2)
	require.NoError(t, err)
	poolCtx, cancelPool := context.WithCancel(context.WithoutCancel(ctx))
	go devices.Populate(poolCtx)
	t.Cleanup(func() { cancelPool(); require.NoError(t, devices.Close(context.WithoutCancel(ctx))) })
	netPool := &serverEROFSNetworkPool{slots: make(map[string]*network.Slot), hostAccess: true}
	t.Cleanup(func() { require.NoError(t, netPool.Close(context.WithoutCancel(ctx))) })
	sandboxes := sandbox.NewSandboxesMap()
	factory := sandbox.NewFactory(ctx, config.BuilderConfig, netPool, devices, flags, hoststats.NewNoopDelivery(), cgroup.NewNoopManager(), network.NewNoopEgressProxy(), nil, sandboxes)
	sbxProxy, err := proxy.NewSandboxProxy(meter, 0, sandboxes, flags)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sbxProxy.Close(context.WithoutCancel(ctx))) })
	info := &service.ServiceInfo{}
	server, err := New(ctx, ServiceConfig{Config: config, Tel: &telemetry.Client{MeterProvider: meter}, NetworkPool: netPool, DevicePool: devices,
		TemplateCache: cache, Info: info, Proxy: sbxProxy, SandboxFactory: factory, Persistence: persistence, FeatureFlags: flags, SbxEventsService: eventservice.NewEventsService(nil)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close(context.WithoutCancel(ctx))) })
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	orchestrator.RegisterSandboxServiceServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() { grpcServer.Stop(); _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///erofs-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	client := orchestrator.NewSandboxServiceClient(conn)
	getStatus := func(api orchestrator.SandboxServiceClient, request *orchestrator.SandboxCheckpointStatusRequest, snapshot orchestrator.CheckpointSnapshotState, runtime orchestrator.CheckpointRuntimeState) *orchestrator.SandboxCheckpointStatusResponse {
		t.Helper()
		response, err := api.CheckpointStatus(ctx, request)
		require.NoError(t, err)
		require.True(t, response.GetNative())
		require.Equal(t, snapshot, response.GetSnapshotState())
		require.Equal(t, runtime, response.GetRuntimeState())
		return response
	}
	receiptClient := func(runtimeFactory *sandbox.Factory) orchestrator.SandboxServiceClient {
		t.Helper()
		// A new Server has no operation table. CheckpointStatus must read the
		// durable receipt and actual process identities, not the old pointers.
		fresh, err := New(ctx, ServiceConfig{Config: config, Tel: &telemetry.Client{MeterProvider: meter}, NetworkPool: netPool, DevicePool: devices,
			TemplateCache: cache, Info: &service.ServiceInfo{}, Proxy: sbxProxy, SandboxFactory: runtimeFactory, Persistence: persistence, FeatureFlags: flags, SbxEventsService: eventservice.NewEventsService(nil)})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, fresh.Close(context.WithoutCancel(ctx))) })
		listener := bufconn.Listen(1 << 20)
		rpc := grpc.NewServer()
		orchestrator.RegisterSandboxServiceServer(rpc, fresh)
		go func() { _ = rpc.Serve(listener) }()
		t.Cleanup(func() { rpc.Stop(); _ = listener.Close() })
		conn, err := grpc.NewClient("passthrough:///erofs-receipt-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, conn.Close()) })
		return orchestrator.NewSandboxServiceClient(conn)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		for _, sbx := range sandboxes.LifecycleItems() {
			if err := sbx.Close(cleanupCtx); err != nil {
				t.Errorf("close %s: %v", sbx.Runtime.SandboxID, err)
			}
		}
		require.Eventually(t, func() bool { return info.OutstandingWork() == 0 }, 10*time.Second, 10*time.Millisecond)
	})
	create := func(buildID string) *sandbox.Sandbox {
		t.Helper()
		token := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
		sandboxID := "g" + uuid.NewString()[:8]
		_, err := client.Create(ctx, &orchestrator.SandboxCreateRequest{Sandbox: &orchestrator.SandboxConfig{
			SandboxId: sandboxID, TemplateId: "erofs-grpc-test", BaseTemplateId: "erofs-grpc-test", BuildId: buildID, ExecutionId: uuid.NewString(), TeamId: uuid.NewString(),
			KernelVersion: meta.Template.KernelVersion, FirecrackerVersion: meta.Template.FirecrackerVersion, EnvdVersion: envdVersion, EnvdAccessToken: &token,
			EnvVars: map[string]string{"EROFS_LIFECYCLE": "ram-disk"}, Vcpu: 1, RamMb: 256, TotalDiskSizeMb: 64, Snapshot: true, MaxSandboxLength: 1}, EndTime: timestamppb.New(time.Now().Add(time.Hour))})
		require.NoError(t, err)
		sbx, ok := sandboxes.Get(sandboxID)
		require.True(t, ok)
		require.True(t, sbx.UsesEROFS())
		return sbx
	}
	sbx := create(baseline.Manifest.ID)
	serverEROFSState(t, ctx, sbx, "/state", 0, 0x53)
	// A rejected fs-only request must not mark the live VM stopping.
	beforePID := serverEROFSPID(t, sbx.Runtime.SandboxID)
	_, err = client.Pause(ctx, &orchestrator.SandboxPauseRequest{SandboxId: sbx.Runtime.SandboxID, BuildId: uuid.NewString(), FilesystemOnly: true})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	still, ok := sandboxes.Get(sbx.Runtime.SandboxID)
	require.True(t, ok)
	require.Same(t, sbx, still)
	require.Equal(t, beforePID, serverEROFSPID(t, sbx.Runtime.SandboxID))
	parentID := baseline.Manifest.ID
	var previousStatusRequest *orchestrator.SandboxCheckpointStatusRequest
	for index, inPlace := range []bool{false, true} {
		datasource.Update(datasource.Flag(featureflags.InPlaceCheckpointFlag.Key()).VariationForAll(inPlace))
		serverEROFSState(t, ctx, sbx, fmt.Sprintf("/write/%d", index+1), index+1, []int{0x53, 0xb7}[index])
		oldLifecycle, oldPID, execution := sbx.LifecycleID, serverEROFSPID(t, sbx.Runtime.SandboxID), sbx.Runtime.ExecutionID
		buildID := uuid.NewString()
		statusRequest := serverEROFSStatusRequest(sbx, buildID)
		preflight := getStatus(client, statusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_UNKNOWN, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
		require.Equal(t, sbx.LifecycleID, preflight.GetLifecycleId())
		require.Equal(t, parentID, preflight.GetRuntimeBuildId())
		checkpointRequest := &orchestrator.SandboxCheckpointRequest{SandboxId: sbx.Runtime.SandboxID, BuildId: buildID}
		checkpointDone := make(chan error, 1)
		if index == 0 {
			require.NoError(t, os.WriteFile(blockMkfs, nil, 0o600))
			t.Cleanup(func() { _ = os.Remove(blockMkfs) })
			go func() { _, err := client.Checkpoint(ctx, checkpointRequest); checkpointDone <- err }()
			require.Eventually(t, func() bool { _, err := os.Stat(enteredMkfs); return err == nil }, 15*time.Second, 10*time.Millisecond)
			getStatus(client, statusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_IN_PROGRESS, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_TRANSITIONING)
			require.NoError(t, os.Remove(blockMkfs))
		} else {
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			netPool.mu.Lock()
			netPool.blockEntered, netPool.blockRelease = entered, release
			netPool.mu.Unlock()
			go func() { _, err := client.Checkpoint(ctx, checkpointRequest); checkpointDone <- err }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			getStatus(client, statusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_TRANSITIONING)
			getStatus(receiptClient(&sandbox.Factory{Sandboxes: sandbox.NewSandboxesMap()}), statusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_TRANSITIONING)
			getStatus(client, previousStatusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_TRANSITIONING)
			unblock()
		}
		select {
		case err = <-checkpointDone:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		require.NoError(t, err)
		sbx, ok = sandboxes.Get(sbx.Runtime.SandboxID)
		require.True(t, ok)
		require.NotEqual(t, oldLifecycle, sbx.LifecycleID)
		require.NotEqual(t, oldPID, serverEROFSPID(t, sbx.Runtime.SandboxID))
		require.Equal(t, execution, sbx.Runtime.ExecutionID)
		committed, err := store.Load(buildID)
		require.NoError(t, err)
		require.Equal(t, parentID, committed.Manifest.ParentID)
		serverEROFSState(t, ctx, sbx, "/state", index+1, []int{0x53, 0xb7}[index])
		committedStatus := getStatus(client, statusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
		require.Equal(t, sbx.LifecycleID, committedStatus.GetLifecycleId())
		require.Equal(t, sbx.Template.Files().BuildID, committedStatus.GetRuntimeBuildId())
		if previousStatusRequest != nil {
			older := getStatus(client, previousStatusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
			require.Equal(t, buildID, older.GetRuntimeBuildId(), "an old receipt must report the current template, not its own build")
		}
		pid := serverEROFSPID(t, sbx.Runtime.SandboxID)
		_, err = client.Checkpoint(ctx, checkpointRequest)
		require.Equal(t, codes.AlreadyExists, status.Code(err))
		live, ok := sandboxes.Get(sbx.Runtime.SandboxID)
		require.True(t, ok)
		require.Same(t, sbx, live)
		require.Equal(t, pid, serverEROFSPID(t, sbx.Runtime.SandboxID))
		for _, mismatch := range []string{"sandbox", "execution", "team"} {
			wrong := serverEROFSStatusRequest(sbx, buildID)
			switch mismatch {
			case "sandbox":
				wrong.SandboxId = "wrong"
			case "execution":
				wrong.ExecutionId = uuid.NewString()
			case "team":
				wrong.TeamId = uuid.NewString()
			}
			_, err := client.CheckpointStatus(ctx, wrong)
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
		}
		fromDisk := getStatus(receiptClient(factory), statusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_RUNNING)
		require.Equal(t, sbx.LifecycleID, fromDisk.GetLifecycleId())
		// Without a recovered live map, a still-alive recorded FC is UNKNOWN,
		// never incorrectly STOPPED or an unregistered RUNNING sandbox.
		getStatus(receiptClient(&sandbox.Factory{Sandboxes: sandbox.NewSandboxesMap()}), statusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_UNKNOWN)
		previousStatusRequest = statusRequest
		parentID = buildID
	}
	// Fail only the next runtime's network assignment, after publication.
	netPool.mu.Lock()
	netPool.failNext = true
	netPool.mu.Unlock()
	failedBuild := uuid.NewString()
	failedStatusRequest := serverEROFSStatusRequest(sbx, failedBuild)
	_, err = client.Checkpoint(ctx, &orchestrator.SandboxCheckpointRequest{SandboxId: sbx.Runtime.SandboxID, BuildId: failedBuild})
	require.Error(t, err)
	require.True(t, orchestrator.IsCheckpointCommittedError(err, failedBuild), "gRPC must preserve the committed snapshot marker: %v", err)
	require.False(t, orchestrator.IsCheckpointCommittedError(err, uuid.NewString()))
	committed, err := store.Load(failedBuild)
	require.NoError(t, err)
	require.Equal(t, parentID, committed.Manifest.ParentID)
	_, ok = sandboxes.Get(sbx.Runtime.SandboxID)
	require.False(t, ok)
	getStatus(client, failedStatusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED)
	getStatus(receiptClient(&sandbox.Factory{Sandboxes: sandbox.NewSandboxesMap()}), failedStatusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_COMMITTED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED)
	retried := create(failedBuild)
	serverEROFSState(t, ctx, retried, "/state", 2, 0xb7)
	pauseBuild := uuid.NewString()
	_, err = client.Pause(ctx, &orchestrator.SandboxPauseRequest{SandboxId: retried.Runtime.SandboxID, TemplateId: retried.Runtime.TemplateID, BuildId: pauseBuild})
	require.NoError(t, err)
	paused, err := store.Load(pauseBuild)
	require.NoError(t, err)
	require.Equal(t, failedBuild, paused.Manifest.ParentID)
	final := create(pauseBuild)
	serverEROFSState(t, ctx, final, "/state", 2, 0xb7)
	// A captured cutoff whose EROFS publication fails stays pending after all
	// process cleanup; receipt reload must not turn it into NOT_COMMITTED.
	captured := create(pauseBuild)
	capturedBuild := uuid.NewString()
	capturedStatusRequest := serverEROFSStatusRequest(captured, capturedBuild)
	require.NoError(t, os.WriteFile(failMkfs, nil, 0o600))
	_, err = client.Checkpoint(ctx, &orchestrator.SandboxCheckpointRequest{SandboxId: captured.Runtime.SandboxID, BuildId: capturedBuild})
	require.Error(t, err)
	require.NoError(t, os.Remove(failMkfs))
	require.NoError(t, captured.Close(ctx))
	getStatus(client, capturedStatusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_CAPTURED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED)
	reloaded := receiptClient(&sandbox.Factory{Sandboxes: sandbox.NewSandboxesMap()})
	getStatus(reloaded, capturedStatusRequest, orchestrator.CheckpointSnapshotState_CHECKPOINT_SNAPSHOT_CAPTURED, orchestrator.CheckpointRuntimeState_CHECKPOINT_RUNTIME_STOPPED)
	wrong := serverEROFSStatusRequest(captured, capturedBuild)
	wrong.TeamId = uuid.NewString()
	_, err = reloaded.CheckpointStatus(ctx, wrong)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	t.Log("real gRPC Create/Pause/Checkpoint, both in-place flag values, committed restore failure and retry passed")
}

func serverEROFSStatusRequest(s *sandbox.Sandbox, buildID string) *orchestrator.SandboxCheckpointStatusRequest {
	return &orchestrator.SandboxCheckpointStatusRequest{SandboxId: s.Runtime.SandboxID, BuildId: buildID, ExecutionId: s.Runtime.ExecutionID, TeamId: s.Runtime.TeamID}
}

func serverEROFSHash(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	require.NoError(t, err)
	return fmt.Sprintf("%x", hash.Sum(nil))
}
func serverEROFSCommand(t *testing.T, ctx context.Context, cmd string, args ...string) []byte {
	t.Helper()
	data, err := exec.CommandContext(ctx, cmd, args...).CombinedOutput()
	require.NoError(t, err, "%s %v: %s", cmd, args, data)
	return data
}
func serverEROFSState(t *testing.T, ctx context.Context, sbx *sandbox.Sandbox, path string, generation, partial int) {
	t.Helper()
	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+sbx.Slot.HostIPString()+":8080"+path, nil)
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	var got struct {
		Generation int    `json:"generation"`
		Memory     [3]int `json:"memory"`
		Disk       [3]int `json:"disk"`
		Partial    int    `json:"partial"`
	}
	require.NoError(t, json.NewDecoder(response.Body).Decode(&got))
	require.Equal(t, generation, got.Generation)
	require.Equal(t, partial, got.Partial)
	if generation == 0 {
		require.Equal(t, [3]int{0x31, 0x42, 0x53}, got.Memory)
		require.Equal(t, got.Memory, got.Disk)
	} else {
		last := 0x53
		if generation == 2 {
			last = 0xb7
		}
		require.Equal(t, [3]int{0xa6, 0, last}, got.Memory)
		require.Equal(t, [3]int{0xa6, 0, 0x53}, got.Disk)
	}
}
func serverEROFSPID(t *testing.T, sandboxID string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	require.NoError(t, err)
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(string(raw), "\x00")
		if len(args) < 3 || filepath.Base(args[0]) != "firecracker" {
			continue
		}
		for _, arg := range args {
			if strings.HasPrefix(filepath.Base(arg), "fc-"+sandboxID+"-") {
				pids = append(pids, pid)
			}
		}
	}
	require.Len(t, pids, 1)
	return pids[0]
}

// A real tap and netns, optionally with a veth route for host envd requests.
// Firewall rules stay inside the namespace; the Factory acquires/releases real
// Slot values through its normal pool API.
type serverEROFSNetworkPool struct {
	mu           sync.Mutex
	slots        map[string]*network.Slot
	hostAccess   bool
	closed       bool
	failNext     bool
	blockEntered chan struct{}
	blockRelease <-chan struct{}
}

func (p *serverEROFSNetworkPool) Get(ctx context.Context, _ *orchestrator.SandboxNetworkConfig, _ network.EgressClass) (*network.Slot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.blockEntered != nil {
		entered, release := p.blockEntered, p.blockRelease
		p.blockEntered, p.blockRelease = nil, nil
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if p.failNext {
		p.failNext = false
		return nil, errors.New("injected post-commit network failure")
	}
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

func (p *serverEROFSNetworkPool) ReturnAsync(ctx context.Context, slot *network.Slot, released network.ReleaseNotify, _ time.Duration) error {
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

func (p *serverEROFSNetworkPool) Close(ctx context.Context) error {
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
