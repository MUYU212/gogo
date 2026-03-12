package core

import (
	"encoding/json"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chainreactors/gogo/v2/engine"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils/iutils"
)

type TaskProgressSnapshot struct {
	Status         string        `json:"status"`
	TaskName       string        `json:"task_name"`
	Target         string        `json:"target"`
	Mode           string        `json:"mode"`
	Ports          string        `json:"ports"`
	TotalTasks     int64         `json:"total_tasks"`
	Completed      int64         `json:"completed_tasks"`
	Percent        float64       `json:"percent"`
	AliveFound     int32         `json:"alive_found"`
	RunSum         int32         `json:"run_sum"`
	ElapsedSecond  int64         `json:"elapsed_seconds"`
	InterruptedAt  string        `json:"interrupted_at"`
	OutputFile     string        `json:"output_file,omitempty"`
	ProgressFile   string        `json:"progress_file"`
	CheckpointFile string        `json:"checkpoint_file,omitempty"`
	Label          string        `json:"label,omitempty"`
	ResumeConfig   *ResumeConfig `json:"resume_config,omitempty"`
}

func startInterruptWatcher(config *Config, started time.Time) func() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		select {
		case <-c:
			finalizeInterrupt(config, started)
		case <-done:
			return
		}
	}()

	return func() {
		signal.Stop(c)
		close(done)
	}
}

func finalizeInterrupt(config *Config, started time.Time) {
	if progress := GetActiveProgress(); progress != nil {
		progress.Finish()
	}

	snapshotFile := writeTaskProgressSnapshot(config, started)

	if config.File != nil {
		config.File.Sync()
	}
	if config.SmartBFile != nil {
		config.SmartBFile.Sync()
	}
	if config.SmartCFile != nil {
		config.SmartCFile.Sync()
	}
	if config.AliveFile != nil {
		config.AliveFile.Sync()
	}
	config.Close()

	if snapshotFile != "" {
		logs.Log.Important("Task progress snapshot: " + snapshotFile)
	}
	logs.Log.Importantf("Interrupted. Alived: %d, Total: %d", Opt.AliveSum, engine.RunSum)
	logs.Log.Close(true)
	os.Exit(130)
}

func writeTaskProgressSnapshot(config *Config, started time.Time) string {
	filename := getProgressFilename(config)
	snapshot := buildTaskProgressSnapshot(config, started, filename)
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		logs.Log.Warnf("write progress snapshot failed: %s", err.Error())
		return ""
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		logs.Log.Warnf("write progress snapshot failed: %s", err.Error())
		return ""
	}
	return filename
}

func buildTaskProgressSnapshot(config *Config, started time.Time, filename string) TaskProgressSnapshot {
	completed := int64(atomic.LoadInt32(&engine.RunSum))
	total := countScanTasks(config.CIDRs, len(config.PortList))
	label := ""

	if progress := GetActiveProgress(); progress != nil {
		ps := progress.Snapshot()
		if ps.Done > 0 {
			completed = ps.Done
		}
		if ps.Total > 0 {
			total = ps.Total
		}
		label = ps.Label
	}
	if config.Results != nil {
		total = countScanTasks(config.Results, len(config.PortList))
	}
	if total < completed {
		total = completed
	}

	percent := 0.0
	if total > 0 {
		percent = float64(completed) / float64(total) * 100
	}

	snapshot := TaskProgressSnapshot{
		Status:         "interrupted",
		TaskName:       config.GetTargetName(),
		Target:         config.GetTarget(),
		Mode:           config.Mod,
		Ports:          config.Ports,
		TotalTasks:     total,
		Completed:      completed,
		Percent:        percent,
		AliveFound:     Opt.AliveSum,
		RunSum:         atomic.LoadInt32(&engine.RunSum),
		ElapsedSecond:  int64(time.Since(started).Seconds()),
		InterruptedAt:  time.Now().Format(time.RFC3339),
		ProgressFile:   filename,
		CheckpointFile: config.CheckpointName,
		Label:          label,
		ResumeConfig:   resumeConfigForSnapshot(config),
	}
	if config.Filename != "" {
		snapshot.OutputFile = config.Filename
	}
	return snapshot
}

func getProgressFilename(config *Config) string {
	basepath := config.FilePath
	if basepath == "" {
		basepath = iutils.GetExcPath()
	}

	if config.Filename != "" {
		return config.Filename + ".progress.json"
	}

	name := progressBasename(config) + ".json"
	if config.Filenamef == "auto" || config.Filenamef == "hidden" {
		name = "." + name
	}
	return path.Join(basepath, name)
}

func progressBasename(config *Config) string {
	target := strings.Replace(config.GetTargetName(), "/", ".", -1)
	target = strings.Replace(target, ":", "", -1)
	target = strings.Replace(target, "\\", "_", -1)
	if len(target) > 10 {
		if i := strings.IndexAny(target, "_"); i != -1 {
			target = target[:i]
		}
	}
	ports := strings.Replace(config.Ports, ",", "_", -1)
	return target + "_" + ports + "_" + config.Mod + "_progress"
}

func resumeConfigForSnapshot(config *Config) *ResumeConfig {
	snapshot := SnapshotConfig(config)
	return &snapshot
}
