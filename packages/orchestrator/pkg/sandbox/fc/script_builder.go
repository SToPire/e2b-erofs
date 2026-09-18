//go:build linux

package fc

import (
	"bytes"
	"fmt"
	"path/filepath"
	txtTemplate "text/template"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/cfg"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/artifact"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage"
)

// startScriptArgs represents the arguments for the start script template
type startScriptArgs struct {
	SandboxDir string

	HostKernelPath    string
	SandboxKernelDir  string
	SandboxKernelFile string

	HostRootfsPath             string
	DeprecatedSandboxRootfsDir string
	SandboxRootfsFile          string

	NamespaceID       string
	FirecrackerPath   string
	FirecrackerSocket string
	SharedMountScript string
}

// StartScriptResult contains the generated script and computed paths
type StartScriptResult struct {
	// Value is the generated firecracker start script
	Value string

	// RootfsPath is the computed rootfs path (with backward compatibility)
	RootfsPath string

	// KernelPath is the computed kernel path
	KernelPath string

	// MemoryPath is the File backend path inside the FC namespace.
	MemoryPath    string
	InitramfsPath string
	pmem          *preparedPmemRootfs
}

const startScriptV1 = `mount --make-rprivate / &&

mount -t tmpfs tmpfs {{ .DeprecatedSandboxRootfsDir }} -o X-mount.mkdir &&
ln -s {{ .HostRootfsPath }} {{ .DeprecatedSandboxRootfsDir }}/{{ .SandboxRootfsFile }} &&

mount -t tmpfs tmpfs {{ .SandboxDir }}/{{ .SandboxKernelDir }} -o X-mount.mkdir &&
ln -s {{ .HostKernelPath }} {{ .SandboxDir }}/{{ .SandboxKernelDir }}/{{ .SandboxKernelFile }} &&

{{ if .SharedMountScript }}{{ .SharedMountScript }} &&
{{ end }}ip netns exec {{ .NamespaceID }} {{ .FirecrackerPath }} --api-sock {{ .FirecrackerSocket }}`

const startScriptV2 = `mount --make-rprivate / &&
mount -t tmpfs tmpfs {{ .SandboxDir }} -o X-mount.mkdir &&

ln -s {{ .HostRootfsPath }} {{ .SandboxDir }}/{{ .SandboxRootfsFile }} &&

mkdir -p {{ .SandboxDir }}/{{ .SandboxKernelDir }} &&
ln -s {{ .HostKernelPath }} {{ .SandboxDir }}/{{ .SandboxKernelDir }}/{{ .SandboxKernelFile }} &&

{{ if .SharedMountScript }}{{ .SharedMountScript }} &&
{{ end }}ip netns exec {{ .NamespaceID }} {{ .FirecrackerPath }} --api-sock {{ .FirecrackerSocket }}`

// StartScriptBuilder handles the creation and execution of firecracker start scripts
type StartScriptBuilder struct {
	builderConfig cfg.BuilderConfig
	templateV1    *txtTemplate.Template
	templateV2    *txtTemplate.Template
}

// NewStartScriptBuilder creates a new StartScriptBuilder instance
func NewStartScriptBuilder(builderConfig cfg.BuilderConfig) *StartScriptBuilder {
	templateV1 := txtTemplate.Must(txtTemplate.New("fc-start-v1").Parse(startScriptV1))
	templateV2 := txtTemplate.Must(txtTemplate.New("fc-start-v2").Parse(startScriptV2))

	return &StartScriptBuilder{
		builderConfig: builderConfig,
		templateV1:    templateV1,
		templateV2:    templateV2,
	}
}

// buildArgs prepares the arguments for the start script template
func (sb *StartScriptBuilder) buildArgs(
	versions Config,
	files *storage.SandboxFiles,
	rootfsPaths RootfsPaths,
	namespaceID string,
) startScriptArgs {
	return startScriptArgs{
		// General
		SandboxDir: sb.builderConfig.SandboxDir,

		// Kernel
		HostKernelPath:    versions.HostKernelPath(sb.builderConfig),
		SandboxKernelDir:  versions.SandboxKernelDir(),
		SandboxKernelFile: artifact.KernelFileName,

		// Rootfs
		HostRootfsPath:             files.SandboxCacheRootfsLinkPath(sb.builderConfig.StorageConfig),
		DeprecatedSandboxRootfsDir: rootfsPaths.DeprecatedSandboxRootfsDir(),
		SandboxRootfsFile:          artifact.RootfsFileName,

		// FC
		NamespaceID:       namespaceID,
		FirecrackerPath:   versions.FirecrackerPath(sb.builderConfig),
		FirecrackerSocket: files.SandboxFirecrackerSocketPath(),
	}
}

// GenerateScript builds and executes the start script template with the provided arguments
func (sb *StartScriptBuilder) GenerateScript(args startScriptArgs, rootfsPaths RootfsPaths) (string, error) {
	var scriptBuffer bytes.Buffer

	// Choose the appropriate template based on the rootfs version
	var template *txtTemplate.Template
	if rootfsPaths.TemplateVersion <= 1 {
		template = sb.templateV1
	} else {
		template = sb.templateV2
	}

	err := template.Execute(&scriptBuffer, args)
	if err != nil {
		return "", fmt.Errorf("error executing fc start script template: %w", err)
	}

	return scriptBuffer.String(), nil
}

// Build creates a complete StartScriptResult with script, args, and computed paths
func (sb *StartScriptBuilder) Build(
	versions Config,
	files *storage.SandboxFiles,
	rootfsPaths RootfsPaths,
	namespaceID string,
	memorySources ...RuntimeSources,
) (*StartScriptResult, error) {
	args := sb.buildArgs(versions, files, rootfsPaths, namespaceID)
	if len(memorySources) > 1 {
		return nil, fmt.Errorf("only one native memory source is allowed")
	}
	if len(memorySources) == 1 && memorySources[0].RawDisk && (!versions.NativeMemory || memorySources[0].Rootfs != nil) {
		return nil, fmt.Errorf("raw build disk requires native memory and cannot also select pmem rootfs")
	}
	if len(memorySources) == 1 && memorySources[0].Rootfs != nil {
		if rootfsPaths.TemplateVersion <= 1 {
			return nil, fmt.Errorf("pmem rootfs cannot use legacy namespace paths")
		}
		return sb.buildPmemScript(versions, files, namespaceID, memorySources[0])
	}
	var hostMemory, memoryPath, sharedRoot string
	if len(memorySources) == 1 {
		hostMemory = memorySources[0].MemoryPath
		if hostMemory != "" {
			if !versions.NativeMemory {
				return nil, fmt.Errorf("shared memory source requires native File restore")
			}
			memoryPath = filepath.Join(args.SandboxDir, args.SandboxKernelDir, "memfile")
		}
	}
	if sb.builderConfig.EROFSSnapshotDir != "" {
		sharedRoot = filepath.Join(sb.builderConfig.EROFSSnapshotDir, ".shared-mounts")
	}
	sharedScript, err := sharedMountScript(sharedRoot, hostMemory, memoryPath)
	if err != nil {
		return nil, err
	}
	args.SharedMountScript = sharedScript

	script, err := sb.GenerateScript(args, rootfsPaths)
	if err != nil {
		return nil, err
	}

	rootfsPath := sb.getRootfsPath(args, rootfsPaths)
	kernelPath := sb.getKernelPath(args)

	return &StartScriptResult{
		Value:      script,
		RootfsPath: rootfsPath,
		KernelPath: kernelPath,
		MemoryPath: memoryPath,
	}, nil
}

// getRootfsPath returns the rootfs path based on the script args, with backward compatibility
func (sb *StartScriptBuilder) getRootfsPath(args startScriptArgs, rootfsPaths RootfsPaths) string {
	rootfsPath := filepath.Join(args.SandboxDir, args.SandboxRootfsFile)
	if rootfsPaths.TemplateVersion <= 1 {
		rootfsPath = filepath.Join(args.DeprecatedSandboxRootfsDir, args.SandboxRootfsFile)
	}

	return rootfsPath
}

// getKernelPath returns the kernel path based on the script args
func (sb *StartScriptBuilder) getKernelPath(args startScriptArgs) string {
	return filepath.Join(args.SandboxDir, args.SandboxKernelDir, args.SandboxKernelFile)
}
