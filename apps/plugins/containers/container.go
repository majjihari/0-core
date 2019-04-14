package containers

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"

	"github.com/threefoldtech/0-core/base/pm"
)

const (
	OVSTag       = "ovs"
	OVSBackPlane = "backplane"
	OVSVXBackend = "vxbackend"
)

var (
	devicesToBind = []string{"random", "urandom", "null"}
)

type container struct {
	id     uint16
	runner pm.Job
	mgr    *Manager
	Args   ContainerCreateArguments `json:"arguments"`
	Root   string                   `json:"root"`
	PID    int                      `json:"pid"`

	zterr       error
	zto         sync.Once
	terminating bool
}

func newContainer(mgr *Manager, id uint16, args ContainerCreateArguments) *container {
	c := &container{
		mgr:  mgr,
		id:   id,
		Args: args,
	}
	c.Root = c.root()
	return c
}

func (c *container) ID() uint16 {
	return c.id
}

func (c *container) dispatch(cmd *pm.Command) error {
	input, err := os.OpenFile(c.pipeIn(), os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	defer input.Close()
	enc := json.NewEncoder(input)
	return enc.Encode(cmd)
}

func (c *container) Arguments() ContainerCreateArguments {
	return c.Args
}

func (c *container) Start() (runner pm.Job, err error) {
	coreID := fmt.Sprintf("core-%d", c.id)

	defer func() {
		if err != nil {
			c.cleanup()
		}
	}()

	if err = c.sandbox(); err != nil {
		log.Errorf("error in container mount: %s", err)
		return
	}

	for _, pipe := range []string{c.pipeIn(), c.pipeOut()} {
		if err := syscall.Mkfifo(pipe, 0644); err != nil {
			return nil, err
		}
	}

	//if err := syscall.Mkfifo()
	if err = c.preStart(); err != nil {
		log.Errorf("error in container prestart: %s", err)
		return
	}

	args := []string{
		"-hostname", c.Args.Hostname,
	}

	if !c.Args.Privileged {
		args = append(args, "-unprivileged")
	}

	//Set a Default Env and merge it with environment map from args
	env := map[string]string{
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME": "/",
	}
	for key, value := range c.Args.Env {
		env[key] = value
	}

	extCmd := &pm.Command{
		ID:      coreID,
		Command: pm.CommandContainer,
		Arguments: pm.MustArguments(
			pm.ContainerCommandArguments{
				Name:        "/coreX",
				Chroot:      c.root(),
				Dir:         "/",
				HostNetwork: c.Args.HostNetwork,
				Args:        args,
				Env:         env,
				Files:       []string{c.pipeIn(), c.pipeOut()},
				Log:         path.Join(BackendBaseDir, c.name(), "container.log"),
			},
		),
	}

	onpid := &pm.PIDHook{
		Action: c.onStart,
	}

	onexit := &pm.ExitHook{
		Action: c.onExit,
	}

	runner, err = c.mgr.api.Run(extCmd, onpid, onexit)
	if err != nil {
		log.Errorf("error in container runner: %s", err)
		return
	}

	c.runner = runner
	return
}

func (c *container) Terminate() error {
	if c.runner == nil {
		return fmt.Errorf("container was not started")
	}
	c.runner.Signal(syscall.SIGTERM)
	c.runner.Wait()
	return nil
}

func (c *container) preStart() error {
	if c.Args.HostNetwork {
		return c.preStartHostNetworking()
	}

	if err := c.preStartIsolatedNetworking(); err != nil {
		return err
	}

	return nil
}

func (c *container) onStart(pid int) {
	c.PID = pid
	if !c.Args.Privileged {
		c.Args.CGroups = append(c.Args.CGroups, DevicesCGroup)
	}

	for _, cgroup := range c.Args.CGroups {
		group, err := c.mgr.cgroup().Get(cgroup.Subsystem(), cgroup.Name())
		if err != nil {
			log.Errorf("can't find cgroup %s", err)
			continue
		}

		group.Task(pid)
	}

	if err := c.postStart(); err != nil {
		log.Errorf("container post start error: %s", err)
		//TODO. Should we shut the container down?
	}

	if err := c.unlock(); err != nil {
		log.Errorf("failed to send unlock magic", err)
	}

	go c.rewind()
	//go c.forward()
}

func (c *container) onExit(state bool) {
	c.terminating = true
	log.Debugf("Container %v exited with state %v", c.id, state)
	tags := strings.Join(c.Args.Tags, ".")
	defer c.cleanup()
	if len(tags) == 0 {
		return
	}
	// logger.Current.LogRecord(&logger.LogRecord{
	// 	Command: fmt.Sprintf("container.%s", tags),
	// 	Message: &stream.Message{
	// 		Meta: stream.NewMeta(0, stream.ExitSuccessFlag),
	// 	},
	// })
}

func (c *container) cleanup() {
	log.Debugf("cleaning up container-%d", c.id)
	defer c.mgr.unsetContainer(c.id)

	c.destroyNetwork()

	if err := c.unMountAll(); err != nil {
		log.Errorf("unmounting container-%d was not clean", err)
	}
}

func (c *container) namespace() error {
	sourceNs := fmt.Sprintf("/proc/%d/ns/net", c.PID)
	os.MkdirAll("/run/netns", 0755)
	targetNs := fmt.Sprintf("/run/netns/%v", c.id)

	if f, err := os.Create(targetNs); err == nil {
		f.Close()
	}

	if err := syscall.Mount(sourceNs, targetNs, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("namespace mount: %s", err)
	}

	return nil
}

func (c *container) postStart() error {
	if c.Args.HostNetwork {
		return nil
	}

	if err := c.postStartIsolatedNetworking(); err != nil {
		log.Errorf("isolated networking error: %s", err)
		return err
	}

	return nil
}