package burst_controller

import (
	"net"
	"sync/atomic"
)

type InterfaceBond struct {
	interfaces []*bondedInterface
}

type bondedInterface struct {
	name   string
	ip     net.IP
	weight int
	active int64
}

func NewInterfaceBond(ifnames ...string) *InterfaceBond {
	bond := &InterfaceBond{}
	for _, name := range ifnames {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var ip net.IP
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && ipnet.IP.To4() != nil {
				ip = ipnet.IP
				break
			}
		}
		if ip == nil {
			continue
		}
		bond.interfaces = append(bond.interfaces, &bondedInterface{
			name:   name,
			ip:     ip,
			weight: 1,
		})
	}
	return bond
}

func (b *InterfaceBond) SelectInterface() string {
	if len(b.interfaces) == 0 {
		return ""
	}

	var selected *bondedInterface
	minRatio := float64(1<<63 - 1)

	for _, iface := range b.interfaces {
		active := float64(atomic.LoadInt64(&iface.active))
		ratio := active / float64(iface.weight)
		if ratio < minRatio {
			minRatio = ratio
			selected = iface
		}
	}

	if selected == nil {
		return ""
	}
	return selected.name
}

func (b *InterfaceBond) ActiveCount() int {
	var total int64
	for _, iface := range b.interfaces {
		total += atomic.LoadInt64(&iface.active)
	}
	return int(total)
}

func (b *InterfaceBond) MarkActive(name string) {
	for _, iface := range b.interfaces {
		if iface.name == name {
			atomic.AddInt64(&iface.active, 1)
			return
		}
	}
}

func (b *InterfaceBond) MarkInactive(name string) {
	for _, iface := range b.interfaces {
		if iface.name == name {
			atomic.AddInt64(&iface.active, -1)
			return
		}
	}
}
