package stream

import (
	"errors"
	"fmt"
	"time"
)

type FramePolicyAction int

const (
	FramePolicyActionNone FramePolicyAction = iota
	FramePolicyActionRehandshake
	FramePolicyActionDropConnection
)

var ErrFramePolicy = errors.New("invalid frame policy")

type FramePolicy struct {
	windowDuration time.Duration
	minFrames      int
	maxBadRatio    float64

	windowStartedAt time.Time
	totalFrames     int
	badSignatures   int

	rehandshakeAlreadyRequested bool
}

func NewFramePolicy(windowDuration time.Duration, minFrames int, maxBadRatio float64) (*FramePolicy, error) {
	if windowDuration <= 0 {
		return nil, fmt.Errorf("%w: window duration must be positive", ErrFramePolicy)
	}

	if minFrames <= 0 {
		return nil, fmt.Errorf("%w: min frames must be positive", ErrFramePolicy)
	}

	if maxBadRatio <= 0 || maxBadRatio >= 1 {
		return nil, fmt.Errorf("%w: max bad ratio must be between 0 and 1", ErrFramePolicy)
	}

	return &FramePolicy{
		windowDuration: windowDuration,
		minFrames:      minFrames,
		maxBadRatio:    maxBadRatio,
	}, nil
}

func (p *FramePolicy) RecordFrame(signatureInvalid bool, now time.Time) FramePolicyAction {
	if p == nil {
		return FramePolicyActionDropConnection
	}

	if p.windowStartedAt.IsZero() {
		p.startNewWindow(now)
	}

	if now.Sub(p.windowStartedAt) > p.windowDuration {
		action := p.evaluateWindow()
		p.startNewWindow(now)
		p.recordCurrentFrame(signatureInvalid)

		if action != FramePolicyActionNone {
			return action
		}

		return FramePolicyActionNone
	}

	p.recordCurrentFrame(signatureInvalid)

	action := p.evaluateWindow()
	if action != FramePolicyActionNone {
		p.startNewWindow(now)
	}

	return action
}

func (p *FramePolicy) startNewWindow(now time.Time) {
	p.windowStartedAt = now
	p.totalFrames = 0
	p.badSignatures = 0
}

func (p *FramePolicy) recordCurrentFrame(signatureInvalid bool) {
	p.totalFrames++
	if signatureInvalid {
		p.badSignatures++
	}
}

func (p *FramePolicy) evaluateWindow() FramePolicyAction {
	if p.totalFrames <= p.minFrames {
		return FramePolicyActionNone
	}

	badRatio := float64(p.badSignatures) / float64(p.totalFrames)
	if badRatio <= p.maxBadRatio {
		return FramePolicyActionNone
	}

	if p.rehandshakeAlreadyRequested {
		return FramePolicyActionDropConnection
	}

	p.rehandshakeAlreadyRequested = true
	return FramePolicyActionRehandshake
}
