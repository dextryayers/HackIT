package main

import (
	"strconv"
	"strings"
)

func parsePorts(pStr string) []int {
	var ports []int
	if pStr == "" {
		return ports
	}
	if pStr == "top100" {
		for k := range commonPorts {
			ports = append(ports, k)
		}
		return unique(ports)
	}
	parts := strings.Split(pStr, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			ranges := strings.Split(part, "-")
			if len(ranges) == 2 {
				start, err1 := strconv.Atoi(ranges[0])
				end, err2 := strconv.Atoi(ranges[1])
				if err1 == nil && err2 == nil {
					for i := start; i <= end; i++ {
						if i > 0 && i <= 65535 {
							ports = append(ports, i)
						}
					}
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	}
	return unique(ports)
}

func unique(intSlice []int) []int {
	keys := make(map[int]bool)
	list := []int{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
