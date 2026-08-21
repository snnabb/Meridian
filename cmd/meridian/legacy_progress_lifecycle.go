package main

import "context"

func (inst *ProxyInstance) drainProgress(ctx context.Context) error {
	if inst == nil || inst.progress == nil {
		return nil
	}
	return inst.progress.Drain(ctx)
}

func (inst *ProxyInstance) closeProgress() {
	if inst != nil && inst.progress != nil {
		inst.progress.Close()
	}
}
