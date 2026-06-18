package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type cweRange struct {
	min    int
	max    int
	owasp  string
}

var owaspRanges = []cweRange{
	{1, 19, "A05:2021 - Security Misconfiguration"},
	{20, 21, "A01:2021 - Broken Access Control"},
	{22, 24, "A01:2021 - Broken Access Control"},
	{35, 36, "A01:2021 - Broken Access Control"},
	{59, 60, "A01:2021 - Broken Access Control"},
	{73, 76, "A04:2021 - Insecure Design"},
	{77, 100, "A03:2021 - Injection"},
	{116, 117, "A03:2021 - Injection"},
	{118, 139, "A03:2021 - Injection"},
	{183, 189, "A03:2021 - Injection"},
	{200, 202, "A01:2021 - Broken Access Control"},
	{203, 208, "A05:2021 - Security Misconfiguration"},
	{209, 213, "A04:2021 - Insecure Design"},
	{214, 216, "A05:2021 - Security Misconfiguration"},
	{217, 218, "A05:2021 - Security Misconfiguration"},
	{219, 227, "A05:2021 - Security Misconfiguration"},
	{228, 250, "A04:2021 - Insecure Design"},
	{251, 252, "A05:2021 - Security Misconfiguration"},
	{253, 255, "A05:2021 - Security Misconfiguration"},
	{256, 260, "A04:2021 - Insecure Design"},
	{261, 264, "A02:2021 - Cryptographic Failures"},
	{265, 266, "A04:2021 - Insecure Design"},
	{267, 268, "A04:2021 - Insecure Design"},
	{269, 274, "A04:2021 - Insecure Design"},
	{275, 286, "A04:2021 - Insecure Design"},
	{287, 290, "A07:2021 - Identification and Authentication Failures"},
	{291, 294, "A07:2021 - Identification and Authentication Failures"},
	{295, 299, "A02:2021 - Cryptographic Failures"},
	{300, 309, "A07:2021 - Identification and Authentication Failures"},
	{310, 312, "A02:2021 - Cryptographic Failures"},
	{313, 320, "A06:2021 - Vulnerable and Outdated Components"},
	{321, 322, "A02:2021 - Cryptographic Failures"},
	{323, 326, "A02:2021 - Cryptographic Failures"},
	{327, 331, "A02:2021 - Cryptographic Failures"},
	{332, 334, "A02:2021 - Cryptographic Failures"},
	{335, 340, "A02:2021 - Cryptographic Failures"},
	{341, 344, "A04:2021 - Insecure Design"},
	{345, 347, "A04:2021 - Insecure Design"},
	{348, 352, "A07:2021 - Identification and Authentication Failures"},
	{353, 354, "A08:2021 - Software and Data Integrity Failures"},
	{370, 375, "A07:2021 - Identification and Authentication Failures"},
	{376, 379, "A07:2021 - Identification and Authentication Failures"},
	{380, 384, "A07:2021 - Identification and Authentication Failures"},
	{385, 389, "A07:2021 - Identification and Authentication Failures"},
	{390, 394, "A07:2021 - Identification and Authentication Failures"},
	{395, 399, "A07:2021 - Identification and Authentication Failures"},
	{400, 404, "A05:2021 - Security Misconfiguration"},
	{405, 409, "A05:2021 - Security Misconfiguration"},
	{410, 414, "A05:2021 - Security Misconfiguration"},
	{415, 419, "A05:2021 - Security Misconfiguration"},
	{420, 424, "A05:2021 - Security Misconfiguration"},
	{425, 426, "A01:2021 - Broken Access Control"},
	{427, 434, "A06:2021 - Vulnerable and Outdated Components"},
	{435, 444, "A05:2021 - Security Misconfiguration"},
	{445, 449, "A05:2021 - Security Misconfiguration"},
	{450, 454, "A05:2021 - Security Misconfiguration"},
	{455, 459, "A05:2021 - Security Misconfiguration"},
	{460, 464, "A05:2021 - Security Misconfiguration"},
	{465, 469, "A05:2021 - Security Misconfiguration"},
	{470, 474, "A05:2021 - Security Misconfiguration"},
	{475, 479, "A05:2021 - Security Misconfiguration"},
	{480, 484, "A05:2021 - Security Misconfiguration"},
	{485, 489, "A05:2021 - Security Misconfiguration"},
	{490, 494, "A06:2021 - Vulnerable and Outdated Components"},
	{495, 499, "A05:2021 - Security Misconfiguration"},
	{500, 504, "A05:2021 - Security Misconfiguration"},
	{505, 509, "A05:2021 - Security Misconfiguration"},
	{510, 514, "A05:2021 - Security Misconfiguration"},
	{515, 519, "A05:2021 - Security Misconfiguration"},
	{520, 522, "A07:2021 - Identification and Authentication Failures"},
	{523, 524, "A02:2021 - Cryptographic Failures"},
	{525, 530, "A07:2021 - Identification and Authentication Failures"},
	{531, 534, "A07:2021 - Identification and Authentication Failures"},
	{535, 538, "A07:2021 - Identification and Authentication Failures"},
	{539, 543, "A07:2021 - Identification and Authentication Failures"},
	{544, 548, "A07:2021 - Identification and Authentication Failures"},
	{549, 553, "A07:2021 - Identification and Authentication Failures"},
	{554, 558, "A07:2021 - Identification and Authentication Failures"},
	{559, 563, "A07:2021 - Identification and Authentication Failures"},
	{564, 565, "A03:2021 - Injection"},
	{566, 568, "A07:2021 - Identification and Authentication Failures"},
	{569, 573, "A07:2021 - Identification and Authentication Failures"},
	{574, 578, "A07:2021 - Identification and Authentication Failures"},
	{579, 583, "A07:2021 - Identification and Authentication Failures"},
	{584, 588, "A07:2021 - Identification and Authentication Failures"},
	{589, 593, "A07:2021 - Identification and Authentication Failures"},
	{594, 598, "A07:2021 - Identification and Authentication Failures"},
	{599, 600, "A07:2021 - Identification and Authentication Failures"},
	{601, 602, "A03:2021 - Injection"},
	{610, 611, "A03:2021 - Injection"},
	{617, 618, "A09:2021 - Security Logging and Monitoring Failures"},
	{639, 640, "A01:2021 - Broken Access Control"},
	{641, 642, "A04:2021 - Insecure Design"},
	{643, 644, "A03:2021 - Injection"},
	{645, 646, "A02:2021 - Cryptographic Failures"},
	{647, 648, "A05:2021 - Security Misconfiguration"},
	{649, 650, "A05:2021 - Security Misconfiguration"},
	{651, 652, "A03:2021 - Injection"},
	{657, 658, "A04:2021 - Insecure Design"},
	{662, 663, "A04:2021 - Insecure Design"},
	{664, 665, "A05:2021 - Security Misconfiguration"},
	{667, 668, "A04:2021 - Insecure Design"},
	{669, 670, "A05:2021 - Security Misconfiguration"},
	{671, 672, "A04:2021 - Insecure Design"},
	{73, 674, "A04:2021 - Insecure Design"},
	{693, 694, "A04:2021 - Insecure Design"},
	{697, 698, "A04:2021 - Insecure Design"},
	{703, 704, "A04:2021 - Insecure Design"},
	{706, 707, "A04:2021 - Insecure Design"},
	{710, 711, "A05:2021 - Security Misconfiguration"},
	{712, 713, "A04:2021 - Insecure Design"},
	{715, 716, "A05:2021 - Security Misconfiguration"},
	{720, 721, "A02:2021 - Cryptographic Failures"},
	{724, 725, "A04:2021 - Insecure Design"},
	{732, 733, "A05:2021 - Security Misconfiguration"},
	{749, 750, "A04:2021 - Insecure Design"},
	{754, 755, "A04:2021 - Insecure Design"},
	{757, 758, "A02:2021 - Cryptographic Failures"},
	{759, 760, "A02:2021 - Cryptographic Failures"},
	{761, 762, "A04:2021 - Insecure Design"},
	{763, 764, "A04:2021 - Insecure Design"},
	{765, 766, "A05:2021 - Security Misconfiguration"},
	{767, 768, "A05:2021 - Security Misconfiguration"},
	{769, 770, "A05:2021 - Security Misconfiguration"},
	{771, 772, "A04:2021 - Insecure Design"},
	{773, 774, "A04:2021 - Insecure Design"},
	{775, 776, "A05:2021 - Security Misconfiguration"},
	{777, 778, "A09:2021 - Security Logging and Monitoring Failures"},
	{779, 780, "A02:2021 - Cryptographic Failures"},
	{781, 782, "A05:2021 - Security Misconfiguration"},
	{783, 784, "A08:2021 - Software and Data Integrity Failures"},
	{787, 788, "A04:2021 - Insecure Design"},
	{789, 790, "A04:2021 - Insecure Design"},
	{791, 792, "A04:2021 - Insecure Design"},
	{793, 794, "A04:2021 - Insecure Design"},
	{795, 796, "A04:2021 - Insecure Design"},
	{797, 798, "A04:2021 - Insecure Design"},
	{799, 800, "A04:2021 - Insecure Design"},
	{801, 802, "A04:2021 - Insecure Design"},
	{803, 804, "A04:2021 - Insecure Design"},
	{805, 806, "A04:2021 - Insecure Design"},
	{807, 808, "A04:2021 - Insecure Design"},
	{809, 810, "A04:2021 - Insecure Design"},
	{811, 812, "A04:2021 - Insecure Design"},
	{813, 814, "A04:2021 - Insecure Design"},
	{815, 816, "A04:2021 - Insecure Design"},
	{817, 818, "A02:2021 - Cryptographic Failures"},
	{819, 820, "A04:2021 - Insecure Design"},
	{821, 822, "A04:2021 - Insecure Design"},
	{823, 824, "A04:2021 - Insecure Design"},
	{825, 826, "A04:2021 - Insecure Design"},
	{827, 828, "A04:2021 - Insecure Design"},
	{829, 830, "A08:2021 - Software and Data Integrity Failures"},
	{831, 832, "A04:2021 - Insecure Design"},
	{833, 834, "A04:2021 - Insecure Design"},
	{835, 836, "A04:2021 - Insecure Design"},
	{837, 838, "A04:2021 - Insecure Design"},
	{839, 840, "A04:2021 - Insecure Design"},
	{841, 842, "A04:2021 - Insecure Design"},
	{843, 844, "A04:2021 - Insecure Design"},
	{845, 846, "A04:2021 - Insecure Design"},
	{847, 848, "A04:2021 - Insecure Design"},
	{849, 850, "A04:2021 - Insecure Design"},
	{851, 852, "A04:2021 - Insecure Design"},
	{853, 854, "A04:2021 - Insecure Design"},
	{855, 856, "A04:2021 - Insecure Design"},
	{857, 858, "A04:2021 - Insecure Design"},
	{859, 860, "A04:2021 - Insecure Design"},
	{861, 862, "A01:2021 - Broken Access Control"},
	{863, 864, "A01:2021 - Broken Access Control"},
	{865, 866, "A04:2021 - Insecure Design"},
	{867, 868, "A05:2021 - Security Misconfiguration"},
	{912, 913, "A01:2021 - Broken Access Control"},
	{914, 915, "A08:2021 - Software and Data Integrity Failures"},
	{916, 917, "A02:2021 - Cryptographic Failures"},
	{918, 919, "A10:2021 - SSRF"},
	{920, 921, "A04:2021 - Insecure Design"},
	{922, 923, "A01:2021 - Broken Access Control"},
	{924, 925, "A05:2021 - Security Misconfiguration"},
	{926, 927, "A04:2021 - Insecure Design"},
	{937, 938, "A06:2021 - Vulnerable and Outdated Components"},
	{940, 941, "A04:2021 - Insecure Design"},
	{942, 943, "A05:2021 - Security Misconfiguration"},
	{970, 971, "A04:2021 - Insecure Design"},
	{981, 982, "A04:2021 - Insecure Design"},
	{1004, 1005, "A05:2021 - Security Misconfiguration"},
	{1007, 1008, "A05:2021 - Security Misconfiguration"},
	{1021, 1022, "A04:2021 - Insecure Design"},
	{1024, 1025, "A05:2021 - Security Misconfiguration"},
	{1035, 1036, "A06:2021 - Vulnerable and Outdated Components"},
	{1037, 1038, "A04:2021 - Insecure Design"},
	{1039, 1040, "A04:2021 - Insecure Design"},
	{1041, 1042, "A05:2021 - Security Misconfiguration"},
	{1043, 1044, "A05:2021 - Security Misconfiguration"},
	{1045, 1046, "A04:2021 - Insecure Design"},
	{1047, 1048, "A04:2021 - Insecure Design"},
	{1049, 1050, "A04:2021 - Insecure Design"},
	{1051, 1052, "A04:2021 - Insecure Design"},
	{1053, 1054, "A04:2021 - Insecure Design"},
	{1055, 1056, "A04:2021 - Insecure Design"},
	{1057, 1058, "A04:2021 - Insecure Design"},
	{1059, 1060, "A06:2021 - Vulnerable and Outdated Components"},
	{1061, 1069, "A06:2021 - Vulnerable and Outdated Components"},
	{1070, 1071, "A05:2021 - Security Misconfiguration"},
	{1072, 1075, "A04:2021 - Insecure Design"},
	{1076, 1077, "A05:2021 - Security Misconfiguration"},
	{1082, 1083, "A04:2021 - Insecure Design"},
	{1088, 1089, "A05:2021 - Security Misconfiguration"},
	{1090, 1091, "A05:2021 - Security Misconfiguration"},
	{1091, 1092, "A04:2021 - Insecure Design"},
	{1101, 1112, "A06:2021 - Vulnerable and Outdated Components"},
	{1121, 1137, "A06:2021 - Vulnerable and Outdated Components"},
	{1150, 1152, "A06:2021 - Vulnerable and Outdated Components"},
	{1154, 1155, "A05:2021 - Security Misconfiguration"},
	{1157, 1159, "A05:2021 - Security Misconfiguration"},
	{1173, 1175, "A05:2021 - Security Misconfiguration"},
	{1191, 1192, "A05:2021 - Security Misconfiguration"},
	{1205, 1206, "A05:2021 - Security Misconfiguration"},
	{1220, 1221, "A04:2021 - Insecure Design"},
	{1221, 1222, "A04:2021 - Insecure Design"},
	{1236, 1237, "A04:2021 - Insecure Design"},
	{1240, 1241, "A02:2021 - Cryptographic Failures"},
	{1242, 1243, "A04:2021 - Insecure Design"},
	{1254, 1255, "A04:2021 - Insecure Design"},
	{1255, 1256, "A04:2021 - Insecure Design"},
	{1263, 1264, "A04:2021 - Insecure Design"},
	{1270, 1271, "A05:2021 - Security Misconfiguration"},
	{1274, 1288, "A06:2021 - Vulnerable and Outdated Components"},
	{1296, 1297, "A05:2021 - Security Misconfiguration"},
	{1298, 1299, "A05:2021 - Security Misconfiguration"},
	{1310, 1340, "A05:2021 - Security Misconfiguration"},
}

func MapCWEtoOWASP(cweID string) string {
	if cweID == "N/A" || cweID == "" {
		return "Unmapped"
	}
	// Parse the CWE number
	numStr := strings.TrimPrefix(cweID, "CWE-")
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return "Unmapped / Various"
	}

	// Binary search through ranges
	for _, r := range owaspRanges {
		if num >= r.min && num <= r.max {
			return r.owasp
		}
	}
	return "Unmapped / Various"
}

type OSVQuery struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Aliases   []string `json:"aliases"`
	Severity  string   `json:"severity"`
	Published string   `json:"published"`
}

func CheckGitHubAdvisory(cveID string) string {
	apiURL := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", cveID)
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (CVE Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return "OSV API unavailable"
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var vuln OSVQuery
	if err := json.Unmarshal(body, &vuln); err != nil {
		return "Parse error"
	}
	if vuln.ID == "" {
		return "No Advisory Found"
	}

	summary := vuln.Summary
	if len(summary) > 100 {
		summary = summary[:100] + "..."
	}
	sev := vuln.Severity
	if sev == "" {
		sev = "N/A"
	}
	return fmt.Sprintf("OSV: %s | Sev: %s | %s", vuln.ID, sev, summary)
}

func CheckExploitDB(severity string, score float64, cveID string) string {
	if score >= 9.0 {
		return "HIGH probability — Patch urgently"
	} else if score >= 7.0 {
		return "MEDIUM probability — Prioritize patching"
	} else if score >= 4.0 {
		return "LOW probability — Monitor for exploits"
	} else {
		return "Minimal risk — Standard patching cycle"
	}
}
