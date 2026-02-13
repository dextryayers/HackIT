package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
)

func runActive(config Config, jobs chan string) {
	if config.Verbose {
		fmt.Println("[*] Running Active Brute Force...")
	}

	// 1. Wildcard Detection
	randName := fmt.Sprintf("hackit-%d.%s", rand.Intn(999999), config.Domain)
	_, err := net.LookupHost(randName)
	if err == nil {
		if config.Verbose {
			fmt.Println("[!] Wildcard DNS detected! Active brute force might produce false positives.")
		}
	}

	// 2. Load Wordlist
	if config.Wordlist != "" {
		count := loadWordlist(config.Wordlist, config.Domain, jobs)
		if config.Verbose {
			fmt.Printf("[*] Loaded %d words from wordlist\n", count)
		}
	} else {
		// Default small list if no wordlist
		defaults := []string{
			"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "test", "dev",
			"shop", "api", "vpn", "secure", "m", "mobile", "admin", "portal", "beta", "stage",
			"staging", "prod", "production", "corp", "internal", "intranet", "git", "gitlab",
			"jenkins", "jira", "kb", "help", "support", "status", "monitor", "grafana",
			"cpanel", "whm", "webdisk", "cpcalendars", "cpcontacts", "webmail", "mail", "autodiscover",
			"autoconfig", "ftp", "forum", "imap", "pop", "smtp", "pop3", "exchange", "owa",
			"cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker", "registry",
			"dashboard", "analytics", "stats", "metrics", "log", "logs", "logging", "search",
			"auth", "login", "signin", "signup", "register", "account", "accounts", "user",
			"users", "profile", "profiles", "member", "members", "client", "clients", "customer",
			"customers", "partner", "partners", "vendor", "vendors", "billing", "payment",
			"finance", "sales", "marketing", "assets", "static", "img", "images", "cdn",
			"media", "files", "download", "downloads", "upload", "uploads", "doc", "docs",
			"documents", "wiki", "confluence", "sharepoint", "office", "email", "chat",
			"slack", "mattermost", "rocket", "teams", "video", "voice", "meet", "meeting",
			"zoom", "conference", "remote", "vpn", "citrix", "rdp", "ssh", "telnet",
			"dns", "ns", "host", "hostname", "whois", "ip", "ipv4", "ipv6",
			"app", "apps", "application", "applications", "mobile", "android", "ios",
			"db", "database", "sql", "mysql", "postgres", "mongo", "redis", "elastic",
			"backup", "backups", "archive", "archives", "old", "new", "temp", "tmp",
			"public", "private", "protected", "secure", "secret", "hidden",
			"test1", "test2", "dev1", "dev2", "stage1", "stage2", "prod1", "prod2",
			"alpha", "demo", "sample", "sandbox", "lab", "labs", "research",
			"gateway", "proxy", "router", "switch", "firewall", "network", "net",
			"wifi", "guest", "staff", "employee", "hr", "legal", "compliance",
		}
		if config.Deep {
			// Deep mode adds even more common subdomains
			defaults = append(defaults, []string{
				"lab", "uat", "preprod", "dr", "dc", "node", "cluster", "balancer",
			"lb", "edge", "mirror", "repo", "npm", "pypi", "docker", "k8s",
			"prometheus", "alert", "monitoring", "logging", "elastic", "kibana",
			"grafana", "vault", "consul", "nomad", "terraform", "ansible",
			"chef", "puppet", "salt", "svn", "hg", "cvs", "bitbucket", "gh",
			"jira", "confluence", "bamboo", "crucible", "fisheye", "bit",
			"cloud", "aws", "s3", "ec2", "rds", "lambda", "sqs", "sns",
			"azure", "blob", "storage", "gcp", "bucket", "gs", "compute",
			"api1", "api2", "api3", "v1", "v2", "v3", "ws", "graphql",
			"oauth", "sso", "saml", "idp", "iam", "keycloak", "okta",
			"jakarta", "bandung", "surabaya", "jogja", "semarang", "medan",
			"makassar", "bali", "papua", "jabar", "jatim", "jateng", "banten",
			"aceh", "sumut", "sumbar", "riau", "jambi", "sumsel", "lampung",
			"kaltim", "kalbar", "kalsel", "kalteng", "sulut", "sulteng", "sulsel",
			"sultra", "maluku", "ntb", "ntt", "dki", "puskas", "data", "arsip",
			"layanan", "ppid", "jdih", "e-office", "simpeg", "kepegawaian",
			"keuangan", "anggaran", "perencanaan", "monev", "pelaporan",
			"bappeda", "diskominfo", "dinas", "upt", "balai", "kantor",
			"sekretariat", "inspektorat", "badan", "biro", "bagian",
			"subbag", "seksi", "bidang", "pusat", "portal", "utama",
			"berita", "pengumuman", "agenda", "galeri", "video", "download",
			"kontak", "faq", "peta", "lokasi", "struktur", "tugas", "fungsi",
			"visi", "misi", "sejarah", "lambang", "profil", "pejabat",
			"pegawai", "struktur", "organisasi", "regulasi", "produk",
			"hukum", "perda", "pergub", "perwal", "perbup", "keputusan",
			"instruksi", "surat", "edaran", "dokumen", "publikasi",
			"statistik", "data", "open", "dashboard", "visualisasi",
			"aplikasi", "sistem", "informasi", "pelayanan", "publik",
			"pengaduan", "aspirasi", "kontak", "hubungi", "kami",
			"pendaftaran", "registrasi", "login", "masuk", "daftar",
			"akun", "profil", "pengaturan", "lupa", "password", "sandi",
			"keamanan", "privasi", "syarat", "ketentuan", "bantuan",
			"panduan", "manual", "tutorial", "video", "gambar", "foto",
			"audio", "suara", "musik", "arsip", "file", "berkas",
			"unduh", "unggah", "kirim", "terima", "proses", "hasil",
			"cetak", "laporan", "rekap", "grafik", "tabel", "list",
			"daftar", "cari", "temukan", "filter", "sortir", "urut",
			"tambah", "ubah", "edit", "hapus", "delete", "simpan",
			"save", "update", "pembaruan", "sinkron", "integrasi",
			"api", "v1", "v2", "v3", "dev", "test", "demo", "sandbox",
			"beta", "alpha", "staging", "prod", "production",
			"server", "host", "node", "cluster", "balancer", "proxy",
			"gateway", "firewall", "security", "auth", "sso", "saml",
			"oauth", "jwt", "token", "key", "secret", "config",
			"setting", "setup", "install", "admin", "administrator",
			"root", "user", "guest", "member", "staff", "employee",
			"manajer", "direktur", "kepala", "ketua", "sekretaris",
			"bendahara", "anggota", "umum", "khusus", "internal",
			"eksternal", "publik", "privat", "rahasia", "terbatas",
			"pemerintah", "negara", "daerah", "provinsi", "kabupaten",
			"kota", "kecamatan", "kelurahan", "desa", "dusun", "rw", "rt",
			"penduduk", "warga", "masyarakat", "sipil", "capil", "sosial",
			"ekonomi", "budaya", "pendidikan", "kesehatan", "pertanian",
			"perikanan", "kehutanan", "pertambangan", "energi", "industri",
			"perdagangan", "koperasi", "ukm", "investasi", "pariwisata",
			"transportasi", "perhubungan", "pekerjaan", "umum", "perumahan",
			"lingkungan", "hidup", "kebersihan", "pertamanan", "tata",
			"ruang", "pertanahan", "agraria", "keamanan", "ketertiban",
			"bencana", "darurat", "sar", "pemadam", "kebakaran",
			"polisi", "tentara", "hukum", "adilan", "ham", "politik",
			"bangsa", "negara", "agama", "ibadah", "sosial", "pemberdayaan",
			"perempuan", "perlindungan", "anak", "pemuda", "olahraga",
			"perpustakaan", "kearsipan", "statistik", "komunikasi",
			"informatika", "persandian", "kepegawaian", "diklat",
			"keuangan", "pendapatan", "pajak", "retribusi", "aset",
			"kekayaan", "pengadaan", "barang", "jasa", "hukum",
			"organisasi", "tata", "laksana", "protokol", "humas",
			"hubungan", "masyarakat", "kerja", "sama", "umum",
			"perlengkapan", "rumah", "tangga", "pimpinan", "staf",
			"ahli", "asisten", "sekda", "gubernur", "wakil", "bupati",
			"walikota", "dprd", "sekwan", "fraksi", "komisi",
			"baleg", "badan", "anggaran", "musyawarah", "pimpinan",
			"paripurna", "sidang", "rapat", "kerja", "kunjungan",
			"studi", "banding", "reses", "aspirasi", "masyarakat",
		}...)
		}
		for _, sub := range defaults {
			jobs <- fmt.Sprintf("%s.%s", sub, config.Domain)
		}
	}
}

func loadWordlist(path string, domain string, jobs chan<- string) int {
	file, err := os.Open(path)
	if err != nil {
		if true { // specific error, maybe always show?
			fmt.Printf("[!] Could not open wordlist: %v\n", err)
		}
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			sub := fmt.Sprintf("%s.%s", word, domain)
			jobs <- sub
			count++
		}
	}
	return count
}

func resolveWorker(jobs <-chan string, wg *sync.WaitGroup, verbose bool) {
	defer wg.Done()
	for domain := range jobs {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		// Resolve
		ips, err := net.LookupHost(domain)
		if err == nil && len(ips) > 0 {
			addResult(domain, ips, "resolved")
			if verbose {
				fmt.Printf("[+] Found: %s (%s)\n", domain, strings.Join(ips, ", "))
			}
		}
	}
}
