package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

type Scheduler struct {
	mu             sync.Mutex
	target         string
	allPorts       []int
	tempo          string
	workers        int
	timeoutMs      int
	batchSize      int
	minRate        float64
	maxRate        float64
	maxRetries     int
}

func NewScheduler(target string, allPorts []int) *Scheduler {
	return &Scheduler{
		target:    target,
		allPorts:  allPorts,
		tempo:     "normal",
		workers:   100,
		timeoutMs: 1000,
		batchSize: 1000,
		minRate:   1.0,
		maxRate:   10.0,
		maxRetries: 3,
	}
}

func (s *Scheduler) SetTempo(tempo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tempo = strings.ToLower(tempo)
	s.applyTempo()
}

func (s *Scheduler) applyTempo() {
	switch s.tempo {
	case "paranoid":
		s.workers = 1
		s.timeoutMs = 15000
		s.batchSize = 50
		s.minRate = 0.15
		s.maxRate = 0.3
		s.maxRetries = 10
	case "sneaky":
		s.workers = 5
		s.timeoutMs = 5000
		s.batchSize = 100
		s.minRate = 0.5
		s.maxRate = 1.0
		s.maxRetries = 6
	case "polite":
		s.workers = 20
		s.timeoutMs = 2000
		s.batchSize = 200
		s.minRate = 1.0
		s.maxRate = 3.0
		s.maxRetries = 4
	case "normal":
		s.workers = 100
		s.timeoutMs = 1000
		s.batchSize = 1000
		s.minRate = 3.0
		s.maxRate = 7.0
		s.maxRetries = 3
	case "aggressive":
		s.workers = 300
		s.timeoutMs = 500
		s.batchSize = 5000
		s.minRate = 5.0
		s.maxRate = 15.0
		s.maxRetries = 2
	case "insane":
		s.workers = 500
		s.timeoutMs = 200
		s.batchSize = 10000
		s.minRate = 10.0
		s.maxRate = 30.0
		s.maxRetries = 1
	default:
		s.workers = 100
		s.timeoutMs = 1000
		s.batchSize = 1000
		s.minRate = 3.0
		s.maxRate = 7.0
		s.maxRetries = 3
	}
}

func (s *Scheduler) Schedule(target string, allPorts []int, tempo string) []ScanJob {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.target = target
	s.allPorts = allPorts
	s.tempo = strings.ToLower(tempo)
	s.applyTempo()

	ordered := s.quantumOrder(allPorts)

	batches := s.createBatches(ordered)

	var jobs []ScanJob
	for _, batch := range batches {
		for i, port := range batch {
			jobs = append(jobs, ScanJob{
				Port:  port,
				Host:  target,
				Index: i,
			})
		}
	}

	return jobs
}

func (s *Scheduler) quantumOrder(ports []int) []int {
	topPriority := []int{
		80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
		8080, 1723, 111, 995, 993, 5900, 587, 8443, 6379, 27017, 5432,
		2375, 9200, 11211, 1433, 1521, 5672, 8000, 8888, 3000, 9090,
		6443, 10250, 2379, 2376, 5985, 5986, 23, 389, 636, 1194, 2049,
		2082, 2083, 2086, 2087, 5222, 5901, 5902, 6667, 6697, 11211,
		16379, 4243, 8500, 2181, 179, 8009, 873, 5060, 161, 123, 500,
		1900, 4500, 1433, 1521, 50000, 5984, 9042, 9092, 8200, 11211,
	}
	highSet := make(map[int]bool, len(topPriority))
	for _, p := range topPriority {
		highSet[p] = true
	}

	medPriority := []int{
		7, 9, 13, 17, 19, 37, 42, 49, 70, 79, 81, 82, 83, 84, 85, 86,
		87, 88, 89, 90, 91, 92, 94, 95, 96, 98, 101, 102, 105, 106, 107,
		109, 113, 115, 117, 118, 119, 123, 129, 138, 144, 145, 146, 147,
		150, 156, 158, 160, 162, 170, 177, 192, 199, 201, 264, 311, 318,
		350, 366, 389, 402, 407, 415, 425, 427, 434, 443, 444, 445, 446,
		464, 465, 475, 491, 497, 500, 502, 504, 510, 512, 513, 514, 515,
		520, 521, 524, 540, 542, 544, 546, 547, 548, 552, 554, 555, 556,
		560, 561, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573,
		574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586,
		587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599,
		600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612,
		613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625,
		626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 636, 637, 638,
		639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650,
		651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663,
		664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676,
		677, 678, 679, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689,
		690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700, 701, 702,
		703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714, 715,
		716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728,
		729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741,
		742, 743, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753, 754,
		755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767,
		768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780,
		781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793,
		794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806,
		807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 819,
		820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832,
		833, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845,
		846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858,
		859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 869, 870, 871,
		872, 873, 874, 875, 876, 877, 878, 879, 880, 881, 882, 883, 884,
		885, 886, 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897,
		898, 899, 900,
	}
	medSet := make(map[int]bool, len(medPriority))
	for _, p := range medPriority {
		medSet[p] = true
	}

	var high, med, rest []int
	for _, p := range ports {
		switch {
		case highSet[p]:
			high = append(high, p)
		case medSet[p]:
			med = append(med, p)
		default:
			rest = append(rest, p)
		}
	}

	sort.Ints(high)
	sort.Ints(med)
	sort.Ints(rest)

	result := make([]int, 0, len(ports))
	result = append(result, high...)
	result = append(result, med...)
	result = append(result, rest...)

	return result
}

func (s *Scheduler) createBatches(ports []int) [][]int {
	if len(ports) == 0 {
		return nil
	}

	batchSize := s.batchSize
	if batchSize <= 0 {
		batchSize = 1000
	}

	total := len(ports)
	numBatches := int(math.Ceil(float64(total) / float64(batchSize)))
	batches := make([][]int, 0, numBatches)

	for i := 0; i < total; i += batchSize {
		end := i + batchSize
		if end > total {
			end = total
		}
		batch := make([]int, end-i)
		copy(batch, ports[i:end])
		batches = append(batches, batch)
	}

	return batches
}

func (s *Scheduler) calcTimeout(batchSize int) time.Duration {
	baseTimeout := time.Duration(s.timeoutMs) * time.Millisecond

	if batchSize <= 0 {
		return baseTimeout
	}

	perPortTime := baseTimeout
	if batchSize > 1 {
		perPortTime = time.Duration(int64(baseTimeout) / int64(batchSize))
	}

	if perPortTime < 10*time.Millisecond {
		perPortTime = 10 * time.Millisecond
	}

	switch s.tempo {
	case "paranoid":
		perPortTime = 15 * time.Second
	case "sneaky":
		perPortTime = 5 * time.Second
	case "polite":
		perPortTime = 2 * time.Second
	case "normal":
		perPortTime = 1 * time.Second
	case "aggressive":
		perPortTime = 500 * time.Millisecond
	case "insane":
		perPortTime = 200 * time.Millisecond
	}

	return perPortTime
}

func (s *Scheduler) AdaptiveWorkerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	base := s.workers
	portCount := len(s.allPorts)

	if portCount > 10000 {
		base = int(float64(base) * 1.5)
	} else if portCount > 50000 {
		base = int(float64(base) * 2.0)
	} else if portCount < 100 {
		base = max2(10, base/2)
	}

	if base < 1 {
		base = 1
	}
	if base > 1000 {
		base = 1000
	}

	return base
}

func (s *Scheduler) EstimatedDuration(ports []int) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	perPort := s.calcTimeout(1)
	total := time.Duration(len(ports)) * perPort

	concurrency := time.Duration(s.AdaptiveWorkerCount())
	if concurrency > 0 {
		total = time.Duration(int64(total) / int64(concurrency))
	}

	overhead := 2 * time.Second
	total += overhead

	return total
}

func (s *Scheduler) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("Scheduler{tempo=%s workers=%d timeout=%dms batch=%d retries=%d}",
		s.tempo, s.workers, s.timeoutMs, s.batchSize, s.maxRetries)
}

func max2(a, b int) int {
	if a > b {
		return a
	}
	return b
}
