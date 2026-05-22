package stream

import (
	"testing"
	"time"
)

func TestFramePolicyAnomalies(t *testing.T) {
	t.Run("ignores_small_sample", func(t *testing.T) {
		policy, err := NewFramePolicy(3*time.Second, 30, 0.2)
		if err != nil {
			t.Fatalf("NewFramePolicy() error = %v", err)
		}

		action := recordFrames(policy, 30, 30, time.Now())
		if action != FramePolicyActionNone {
			t.Fatalf("action = %v, want %v", action, FramePolicyActionNone)
		}
	})

	t.Run("requests_rehandshake", func(t *testing.T) {
		policy, err := NewFramePolicy(3*time.Second, 30, 0.2)
		if err != nil {
			t.Fatalf("NewFramePolicy() error = %v", err)
		}

		now := time.Now()
		action := recordFrames(policy, 31, 7, now)
		if action != FramePolicyActionRehandshake {
			t.Fatalf("action = %v, want %v", action, FramePolicyActionRehandshake)
		}
	})
}

func recordFrames(policy *FramePolicy, total int, bad int, now time.Time) FramePolicyAction {
	action := FramePolicyActionNone
	for i := 0; i < total; i++ {
		current := policy.RecordFrame(i < bad, now)
		if current != FramePolicyActionNone {
			action = current
		}
	}
	return action
}
