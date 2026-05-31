package main

import (
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/fatih/color"
	"go.uber.org/zap"
)

// ChannelHopper manages asynchronous thread-safe wireless channel hopping
type ChannelHopper struct {
	Interface string
	Channels  []int
	StopChan  chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	Logger    *zap.Logger
}

// NewChannelHopper initializes a safe channel hopper
func NewChannelHopper(iface string, channels []int) *ChannelHopper {
	logger, _ := zap.NewProduction()
	return &ChannelHopper{
		Interface: iface,
		Channels:  channels,
		StopChan:  make(chan struct{}),
		Logger:    logger,
	}
}

// Start begins hopping through the provided 802.11 channels
func (c *ChannelHopper) Start(intervalMs int) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		idx := 0
		ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
		defer ticker.Stop()

		c.Logger.Info("Started high-speed channel hopper", zap.String("interface", c.Interface))

		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				ch := c.Channels[idx]
				idx = (idx + 1) % len(c.Channels)
				c.mu.Unlock()

				c.setChannel(ch)
			case <-c.StopChan:
				c.Logger.Info("Stopping channel hopper", zap.String("interface", c.Interface))
				return
			}
		}
	}()
}

// Stop gracefully signals the hop routine to terminate
func (c *ChannelHopper) Stop() {
	close(c.StopChan)
	c.wg.Wait()
	c.Logger.Sync()
}

func (c *ChannelHopper) setChannel(ch int) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Native windows channel lock (experimental/driver-specific)
		cmd = exec.Command("netsh", "wlan", "set", "hostednetwork", "channel="+strconv.Itoa(ch))
	} else {
		cmd = exec.Command("iw", "dev", c.Interface, "set", "channel", strconv.Itoa(ch))
	}

	err := cmd.Run()
	if err != nil {
		color.Red("[GO-HOPPER] Failed to set channel %d: %v", ch, err)
		c.Logger.Warn("Channel hop failed", zap.Int("channel", ch), zap.Error(err))
	} else {
		color.Cyan("[GO-HOPPER] Locked to Channel %d", ch)
		c.Logger.Debug("Channel lock OK", zap.Int("channel", ch))
	}
}
