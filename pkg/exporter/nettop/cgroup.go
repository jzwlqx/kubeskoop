package nettop

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

var (
	cgroupRoot   = ""
	cgroupV2Mode = false
)

func init() {
	root, err := lookupCgroupRoot()
	if err != nil {
		log.Errorf("failed lookup cgroup root: %v", err)
		return
	}
	cgroupRoot = root
	cgroupV2Mode = isCgroupV2()
}

// isCgroupV2 checks if system is using cgroup v2
func isCgroupV2() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

func lookupCgroupRoot() (string, error) {
	// TODO lookup from /proc/mount
	return "/sys/fs/cgroup", nil
}

func tasksInsidePodCgroup(path string, absolutePath bool) []int {
	//TODO watch file changes by inotify
	if cgroupRoot == "" || path == "" {
		return nil
	}
	base := path
	if !absolutePath {
		if cgroupV2Mode {
			base = filepath.Join(cgroupRoot, path)
		} else {
			base = filepath.Join(cgroupRoot, "memory", path)
		}
	}

	// Determine the tasks file name based on cgroup version
	tasksFileName := "tasks"
	if cgroupV2Mode {
		tasksFileName = "cgroup.threads"
	}

	m := make(map[int]int)
	err := filepath.Walk(base, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, "/"+tasksFileName) {
			tasks, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed read cgroup tasks %s: %w", path, err)
			}
			for _, s := range strings.Split(string(tasks), "\n") {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				i, err := strconv.Atoi(s)
				if err != nil {
					return fmt.Errorf("invalid tasks pid format in %s : %w", path, err)
				}
				m[i] = 1
			}
		}
		return nil
	})

	if err != nil {
		log.Errorf("failed list tasks: %v", err)
	}

	var ret []int
	for k := range m {
		ret = append(ret, k)
	}
	return ret
}
