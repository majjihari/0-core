package containers

type hooks struct {
	mgr  *containerManager
	args *ContainerCreateArguments

	coreID string
	pid    int
}

func (h *hooks) onPID(pid int) {
	h.pid = pid
	h.mgr.postBind(h.coreID, pid)
}

func (h *hooks) onExit(state bool) {
	log.Debugf("Container %d exited with state %v", h.coreID, state)
	h.mgr.unbind(h.coreID, h.pid, h.args)
}
