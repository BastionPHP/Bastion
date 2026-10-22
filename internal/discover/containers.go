package discover

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

// Container is a running container found through a runtime CLI.
type Container struct {
	Runtime string // docker, podman
	ID      string
	Name    string
	Image   string
	PID     int
	Env     map[string]string
}

// Containers lists running containers for every runtime CLI on PATH.
// Errors from one runtime (daemon down, no permission) are returned as
// warnings and do not stop the scan.
func Containers(ctx context.Context) ([]Container, []string) {
	var out []Container
	var warns []string
	for _, rt := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(rt); err != nil {
			continue
		}
		cs, err := listContainers(ctx, rt)
		if err != nil {
			warns = append(warns, rt+": "+err.Error())
			continue
		}
		out = append(out, cs...)
	}
	return out, warns
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
		return out, constErr(strings.TrimSpace(firstLine(string(ee.Stderr))))
	}
	return out, err
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

func listContainers(ctx context.Context, rt string) ([]Container, error) {
	ids, err := run(ctx, rt, "ps", "-q", "--no-trunc")
	if err != nil {
		return nil, err
	}
	idList := strings.Fields(string(ids))
	if len(idList) == 0 {
		return nil, nil
	}
	raw, err := run(ctx, rt, append([]string{"inspect"}, idList...)...)
	if err != nil {
		return nil, err
	}
	var docs []struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image string   `json:"Image"`
			Env   []string `json:"Env"`
		} `json:"Config"`
		State struct {
			Pid int `json:"Pid"`
		} `json:"State"`
	}
	if err := json.Unmarshal(raw, &docs); err != nil {
		return nil, err
	}
	var out []Container
	for _, d := range docs {
		c := Container{Runtime: rt, ID: d.ID, Name: strings.TrimPrefix(d.Name, "/"), Image: d.Config.Image, PID: d.State.Pid, Env: map[string]string{}}
		for _, e := range d.Config.Env {
			if k, v, ok := strings.Cut(e, "="); ok {
				c.Env[k] = v
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// Exec runs a command inside the container.
func (c Container) Exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	return run(ctx, c.Runtime, append([]string{"exec", c.ID, name}, args...)...)
}
