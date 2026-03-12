package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/utils/iutils"
)

type ResumeConfig struct {
	IP            string     `json:"ip,omitempty"`
	IPlist        []string   `json:"ips,omitempty"`
	Ports         string     `json:"ports"`
	ListFile      string     `json:"list_file,omitempty"`
	JsonFile      string     `json:"json_file,omitempty"`
	Threads       int        `json:"threads"`
	Mod           string     `json:"mod"`
	NoScan        bool       `json:"no_scan,omitempty"`
	AliveSprayMod []string   `json:"alive_spray_mod,omitempty"`
	PortSpray     bool       `json:"port_spray,omitempty"`
	Exploit       string     `json:"exploit,omitempty"`
	VersionLevel  int        `json:"version_level,omitempty"`
	Delay         int        `json:"delay"`
	HttpsDelay    int        `json:"https_delay"`
	PortProbe     string     `json:"port_probe,omitempty"`
	IpProbe       string     `json:"ip_probe,omitempty"`
	NoSpray       bool       `json:"no_spray,omitempty"`
	Debug         bool       `json:"debug,omitempty"`
	Opsec         bool       `json:"opsec,omitempty"`
	Filename      string     `json:"filename,omitempty"`
	FilePath      string     `json:"file_path,omitempty"`
	Outputf       string     `json:"output,omitempty"`
	FileOutputf   string     `json:"file_output,omitempty"`
	Filenamef     string     `json:"filenamef,omitempty"`
	Compress      bool       `json:"compress"`
	Tee           bool       `json:"tee,omitempty"`
	ShowProgress  bool       `json:"show_progress"`
	Filters       []string   `json:"filters,omitempty"`
	FilterOr      bool       `json:"filter_or,omitempty"`
	OutputFilters [][]string `json:"output_filters,omitempty"`
	ScanFilters   [][]string `json:"scan_filters,omitempty"`
	ExcludeCIDRs  []string   `json:"exclude_cidrs,omitempty"`
}

type ResumeState struct {
	completed map[string]struct{}
	mu        sync.RWMutex
}

func scopedTaskKey(scope string, tc targetConfig) string {
	return scope + "|" + taskKey(tc)
}

func NewResumeState() *ResumeState {
	return &ResumeState{completed: make(map[string]struct{})}
}

func (rs *ResumeState) Add(key string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if _, ok := rs.completed[key]; ok {
		return false
	}
	rs.completed[key] = struct{}{}
	return true
}

func (rs *ResumeState) Has(key string) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	_, ok := rs.completed[key]
	return ok
}

func (rs *ResumeState) Len() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return len(rs.completed)
}

func SnapshotConfig(config *Config) ResumeConfig {
	snapshot := ResumeConfig{
		IP:            config.IP,
		IPlist:        append([]string(nil), config.IPlist...),
		Ports:         config.Ports,
		ListFile:      config.ListFile,
		JsonFile:      config.JsonFile,
		Threads:       config.Threads,
		Mod:           config.Mod,
		NoScan:        config.NoScan,
		AliveSprayMod: append([]string(nil), config.AliveSprayMod...),
		PortSpray:     config.PortSpray,
		Exploit:       config.RunnerOpt.Exploit,
		VersionLevel:  config.RunnerOpt.VersionLevel,
		Delay:         config.RunnerOpt.Delay,
		HttpsDelay:    config.RunnerOpt.HttpsDelay,
		PortProbe:     config.PortProbe,
		IpProbe:       config.IpProbe,
		NoSpray:       config.NoSpray,
		Debug:         config.RunnerOpt.Debug,
		Opsec:         config.RunnerOpt.Opsec,
		Filename:      config.Filename,
		FilePath:      config.FilePath,
		Outputf:       config.Outputf,
		FileOutputf:   config.FileOutputf,
		Filenamef:     config.Filenamef,
		Compress:      config.Compress,
		Tee:           config.Tee,
		ShowProgress:  config.ShowProgress,
		Filters:       append([]string(nil), config.Filters...),
		FilterOr:      config.FilterOr,
		OutputFilters: cloneFilterGroups(config.OutputFilters),
		ScanFilters:   cloneFilterGroups(config.RunnerOpt.ScanFilters),
	}
	if config.Excludes != nil {
		for _, cidr := range config.Excludes {
			snapshot.ExcludeCIDRs = append(snapshot.ExcludeCIDRs, cidr.String())
		}
	}
	return snapshot
}

func (rc ResumeConfig) ToConfig() Config {
	config := Config{
		GOGOConfig: &parsers.GOGOConfig{
			IP:            rc.IP,
			IPlist:        append([]string(nil), rc.IPlist...),
			Ports:         rc.Ports,
			ListFile:      rc.ListFile,
			JsonFile:      rc.JsonFile,
			Threads:       rc.Threads,
			Mod:           rc.Mod,
			NoScan:        rc.NoScan,
			AliveSprayMod: append([]string(nil), rc.AliveSprayMod...),
			PortSpray:     rc.PortSpray,
			Exploit:       rc.Exploit,
			VersionLevel:  rc.VersionLevel,
		},
		RunnerOpt: &RunnerOption{
			Exploit:      rc.Exploit,
			VersionLevel: rc.VersionLevel,
			Delay:        rc.Delay,
			HttpsDelay:   rc.HttpsDelay,
			ScanFilters:  cloneFilterGroups(rc.ScanFilters),
			Debug:        rc.Debug,
			Opsec:        rc.Opsec,
		},
		PortProbe:     rc.PortProbe,
		IpProbe:       rc.IpProbe,
		NoSpray:       rc.NoSpray,
		Filename:      rc.Filename,
		FilePath:      rc.FilePath,
		Outputf:       rc.Outputf,
		FileOutputf:   rc.FileOutputf,
		Filenamef:     rc.Filenamef,
		Compress:      rc.Compress,
		Tee:           rc.Tee,
		ShowProgress:  rc.ShowProgress,
		Filters:       append([]string(nil), rc.Filters...),
		FilterOr:      rc.FilterOr,
		OutputFilters: cloneFilterGroups(rc.OutputFilters),
		IsResume:      true,
	}
	if len(rc.ExcludeCIDRs) > 0 {
		config.Excludes = utils.ParseCIDRs(rc.ExcludeCIDRs)
		config.RunnerOpt.ExcludeCIDRs = config.Excludes
	}
	return config
}

func LoadResumeSnapshot(filename string) (*TaskProgressSnapshot, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var snapshot TaskProgressSnapshot
	if err := json.Unmarshal(content, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.ResumeConfig == nil {
		return nil, fmt.Errorf("resume snapshot %s missing resume config", filename)
	}
	return &snapshot, nil
}

func loadResumeState(filename string) (*ResumeState, error) {
	state := NewResumeState()
	if filename == "" {
		return state, nil
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, err
	}

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		state.completed[line] = struct{}{}
	}
	return state, nil
}

func cloneFilterGroups(in [][]string) [][]string {
	if len(in) == 0 {
		return nil
	}
	out := make([][]string, 0, len(in))
	for _, group := range in {
		out = append(out, append([]string(nil), group...))
	}
	return out
}

func buildResumeConfig(base Config) (Config, error) {
	if base.ResumeFile == "" {
		return base, nil
	}

	snapshot, err := LoadResumeSnapshot(base.ResumeFile)
	if err != nil {
		return Config{}, err
	}
	if snapshot.ResumeConfig == nil {
		return Config{}, fmt.Errorf("resume snapshot %s missing resume config", base.ResumeFile)
	}
	if snapshot.ResumeConfig.Mod != Default {
		return Config{}, fmt.Errorf("resume only supports default scan mode currently, snapshot mode: %s", snapshot.ResumeConfig.Mod)
	}

	config := snapshot.ResumeConfig.ToConfig()
	config.ResumeFile = base.ResumeFile
	config.IsResume = true
	config.ShowProgress = base.ShowProgress
	if base.Filename != "" {
		config.Filename = base.Filename
	}
	if base.FilePath != "" {
		config.FilePath = base.FilePath
	}
	if base.Filenamef != "" {
		config.Filenamef = base.Filenamef
	}
	if base.Threads != 0 {
		config.Threads = base.Threads
		config.GOGOConfig.Threads = base.Threads
	}
	if base.RunnerOpt.Delay != 0 {
		config.RunnerOpt.Delay = base.RunnerOpt.Delay
	}
	if base.RunnerOpt.HttpsDelay != 0 {
		config.RunnerOpt.HttpsDelay = base.RunnerOpt.HttpsDelay
	}
	config.ProgressFile = snapshot.ProgressFile
	config.CheckpointName = snapshot.CheckpointFile
	return config, nil
}

func prepareResumeTracking(config *Config) error {
	if !config.IsScan() || config.Mod != Default {
		return nil
	}

	if config.CheckpointName == "" {
		config.CheckpointName = getCheckpointFilename(config)
	}
	if config.ProgressFile == "" {
		config.ProgressFile = getProgressFilename(config)
	}

	state, err := loadResumeState(config.CheckpointName)
	if err != nil {
		return err
	}
	config.ResumeState = state
	if config.IsResume {
		logs.Log.Importantf("Resume scan from %s, loaded %d completed tasks", config.ResumeFile, state.Len())
	}
	return nil
}

func getCheckpointFilename(config *Config) string {
	basepath := config.FilePath
	if basepath == "" {
		basepath = iutils.GetExcPath()
	}

	if config.Filename != "" {
		return config.Filename + ".checkpoint"
	}

	name := progressBasename(config) + ".checkpoint"
	if config.Filenamef == "auto" || config.Filenamef == "hidden" {
		name = "." + name
	}
	return path.Join(basepath, name)
}

func taskKey(tc targetConfig) string {
	return tc.ip + ":" + tc.port
}

func getResumeState(config Config) *ResumeState {
	if config.ResumeState == nil {
		return nil
	}
	if state, ok := config.ResumeState.(*ResumeState); ok {
		return state
	}
	return nil
}

func shouldSkipTask(config Config, scope string, tc targetConfig) bool {
	state := getResumeState(config)
	if state == nil {
		return false
	}
	return state.Has(scopedTaskKey(scope, tc))
}

func remainingTasks(config Config, scope string, total int64) int64 {
	state := getResumeState(config)
	if state == nil {
		return total
	}
	remaining := total - completedTasks(config, scope)
	if remaining < 0 {
		return 0
	}
	return remaining
}

func completedTasks(config Config, scope string) int64 {
	state := getResumeState(config)
	if state == nil {
		return 0
	}
	done := int64(0)
	state.mu.RLock()
	for key := range state.completed {
		if strings.HasPrefix(key, scope+"|") {
			done++
		}
	}
	state.mu.RUnlock()
	return done
}

func markTaskCompleted(config Config, scope string, tc targetConfig) {
	state := getResumeState(config)
	key := scopedTaskKey(scope, tc)
	if state != nil && !state.Add(key) {
		return
	}
	if config.CheckpointFile != nil {
		_ = config.CheckpointFile.WriteLine(key)
	}
}
