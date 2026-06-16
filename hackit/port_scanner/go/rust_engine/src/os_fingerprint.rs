use std::ffi::{CStr, CString};
use std::net::TcpStream;
use std::os::raw::c_char;
use std::process::Command;
use std::time::Duration;
use std::io::{Read, Write};

#[repr(C)]
pub struct RustOSInfo {
    pub os_name: *mut c_char,
    pub os_version: *mut c_char,
    pub os_family: *mut c_char,
    pub accuracy: i32,
    pub ttl: i32,
    pub window_size: i32,
    pub evidence: *mut c_char,
}

#[derive(Debug, Clone, Copy)]
struct OSSig {
    name: &'static str,
    version: &'static str,
    family: &'static str,
    ttl_min: i32,
    ttl_max: i32,
    window_sizes: &'static [i32],
    mss: i32,
    wscale: i8,
    df: i8,
    timestamps: i8,
    sack: i8,
    keywords: &'static [&'static str],
    confidence: u8,
}

const OS_FP: &[OSSig] = &[
    // ─── WINDOWS ──────────────────────────────────────────────────
    OSSig { name: "Windows", version: "95/98/Me", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[8192, 17520], mss: 1460, wscale: -1, df: 1, timestamps: 0, sack: 0, keywords: &["windows 95","windows 98","windows me"], confidence: 70 },
    OSSig { name: "Windows", version: "NT 4.0", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[8192, 65535], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["windows nt"], confidence: 75 },
    OSSig { name: "Windows", version: "2000", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[17520, 65535, 8192], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["windows 2000","nt 5.0"], confidence: 80 },
    OSSig { name: "Windows", version: "XP (SP1-)", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[65535, 16384], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["windows xp","nt 5.1"], confidence: 85 },
    OSSig { name: "Windows", version: "XP SP2/SP3", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[65535], mss: 1460, wscale: 0, df: 1, timestamps: 1, sack: 1, keywords: &["windows xp","nt 5.1"], confidence: 88 },
    OSSig { name: "Windows", version: "Server 2003", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[65535, 16384], mss: 1460, wscale: 1, df: 1, timestamps: 0, sack: 1, keywords: &["server 2003","nt 5.2"], confidence: 85 },
    OSSig { name: "Windows", version: "Vista", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[8192, 16384], mss: 1460, wscale: 2, df: 1, timestamps: 1, sack: 1, keywords: &["windows vista","nt 6.0"], confidence: 85 },
    OSSig { name: "Windows", version: "Server 2008", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[8192, 16384, 64240], mss: 1460, wscale: 2, df: 1, timestamps: 1, sack: 1, keywords: &["server 2008","nt 6.0"], confidence: 85 },
    OSSig { name: "Windows", version: "7", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[8192, 16384, 65535], mss: 1460, wscale: 2, df: 1, timestamps: 1, sack: 1, keywords: &["windows 7","nt 6.1"], confidence: 90 },
    OSSig { name: "Windows", version: "Server 2008 R2", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[8192, 64240], mss: 1460, wscale: 6, df: 1, timestamps: 1, sack: 1, keywords: &["server 2008 r2","nt 6.1"], confidence: 88 },
    OSSig { name: "Windows", version: "8 / 8.1", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[64240, 65535], mss: 1460, wscale: 8, df: 1, timestamps: 1, sack: 1, keywords: &["windows 8","windows 8.1","nt 6.2","nt 6.3"], confidence: 90 },
    OSSig { name: "Windows", version: "Server 2012 / R2", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[64240, 65535], mss: 1460, wscale: 8, df: 1, timestamps: 1, sack: 1, keywords: &["server 2012","nt 6.2","nt 6.3"], confidence: 88 },
    OSSig { name: "Windows", version: "10 (v1507-1709)", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[64240, 65535], mss: 1460, wscale: 8, df: 1, timestamps: 1, sack: 1, keywords: &["windows 10","nt 10.0"], confidence: 92 },
    OSSig { name: "Windows", version: "10 (v1803-22H2)", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[64240, 65535], mss: 1460, wscale: 8, df: 1, timestamps: 1, sack: 1, keywords: &["windows 10","nt 10.0"], confidence: 93 },
    OSSig { name: "Windows", version: "11", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[65535, 64240], mss: 1460, wscale: 8, df: 1, timestamps: 1, sack: 1, keywords: &["windows 11","nt 10.0"], confidence: 95 },
    OSSig { name: "Windows", version: "Server 2016", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[64240, 65535], mss: 1460, wscale: 8, df: 1, timestamps: 1, sack: 1, keywords: &["server 2016","nt 10.0"], confidence: 92 },
    OSSig { name: "Windows", version: "Server 2019", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[64240, 65535], mss: 1460, wscale: 8, df: 1, timestamps: 1, sack: 1, keywords: &["server 2019","nt 10.0"], confidence: 92 },
    OSSig { name: "Windows", version: "Server 2022 / 2025", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[65535, 64240], mss: 1460, wscale: 8, df: 1, timestamps: 1, sack: 1, keywords: &["server 2022","server 2025","nt 10.0"], confidence: 93 },
    // ─── LINUX KERNEL GENERATIONS ──────────────────────────────────
    OSSig { name: "Linux", version: "2.4.x", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[5840, 5792, 32120], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 1, keywords: &[], confidence: 85 },
    OSSig { name: "Linux", version: "2.6.x (early)", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[5840, 5792], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 1, keywords: &[], confidence: 85 },
    OSSig { name: "Linux", version: "2.6.x", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[5792, 5840, 29200], mss: 1460, wscale: 7, df: 1, timestamps: 0, sack: 1, keywords: &[], confidence: 88 },
    OSSig { name: "Linux", version: "3.x", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 5792, 32736], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &[], confidence: 90 },
    OSSig { name: "Linux", version: "3.x (tuned)", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 32736], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &[], confidence: 90 },
    OSSig { name: "Linux", version: "4.x", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 64240, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &[], confidence: 92 },
    OSSig { name: "Linux", version: "5.x", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[64240, 65535, 131072], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &[], confidence: 93 },
    OSSig { name: "Linux", version: "6.x+", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072, 262144], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &[], confidence: 95 },
    OSSig { name: "Linux", version: "Embedded / IoT", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[5840, 14600, 16384, 8192], mss: 1460, wscale: 3, df: 1, timestamps: 0, sack: 1, keywords: &["busybox","buildroot","yocto"], confidence: 75 },
    // ─── LINUX DISTROS ────────────────────────────────────────────
    OSSig { name: "Ubuntu", version: "14.04 LTS", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 5792], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["ubuntu","14.04"], confidence: 95 },
    OSSig { name: "Ubuntu", version: "16.04 LTS", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 64240], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["ubuntu","16.04","xenial"], confidence: 95 },
    OSSig { name: "Ubuntu", version: "18.04 LTS", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[64240, 29200], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["ubuntu","18.04","bionic"], confidence: 95 },
    OSSig { name: "Ubuntu", version: "20.04 LTS", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[64240, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["ubuntu","20.04","focal"], confidence: 95 },
    OSSig { name: "Ubuntu", version: "22.04 LTS", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[64240, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["ubuntu","22.04","jammy"], confidence: 95 },
    OSSig { name: "Ubuntu", version: "23.04-24.10", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["ubuntu","23.04","23.10","24.04","24.10"], confidence: 95 },
    OSSig { name: "Debian", version: "8 (Jessie)", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[5840, 29200], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["debian","jessie"], confidence: 92 },
    OSSig { name: "Debian", version: "9 (Stretch)", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 5840], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["debian","stretch"], confidence: 92 },
    OSSig { name: "Debian", version: "10 (Buster)", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 64240], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["debian","buster"], confidence: 93 },
    OSSig { name: "Debian", version: "11 (Bullseye)", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[64240, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["debian","bullseye"], confidence: 93 },
    OSSig { name: "Debian", version: "12 (Bookworm)", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 64240], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["debian","bookworm"], confidence: 93 },
    OSSig { name: "Debian", version: "13 (Trixie)", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["debian","trixie"], confidence: 90 },
    OSSig { name: "CentOS", version: "6", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[5840, 14600], mss: 1460, wscale: 7, df: 1, timestamps: 0, sack: 1, keywords: &["centos","el6"], confidence: 90 },
    OSSig { name: "CentOS", version: "7", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[14600, 29200], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["centos","el7"], confidence: 92 },
    OSSig { name: "CentOS", version: "8", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 64240], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["centos","el8"], confidence: 92 },
    OSSig { name: "CentOS/ Rocky/ Alma", version: "9", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[64240, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["centos stream","rocky","almalinux","el9"], confidence: 92 },
    OSSig { name: "RHEL", version: "7", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[14600, 29200], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["red hat","rhel el7"], confidence: 90 },
    OSSig { name: "RHEL", version: "8", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 64240], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["red hat","rhel el8"], confidence: 90 },
    OSSig { name: "RHEL", version: "9", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[64240, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["red hat","rhel el9"], confidence: 92 },
    OSSig { name: "Fedora", version: "33-40", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 64240, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["fedora"], confidence: 90 },
    OSSig { name: "Arch Linux", version: "Rolling", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 65535, 131072], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["arch","artix"], confidence: 85 },
    OSSig { name: "Gentoo", version: "Rolling", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["gentoo"], confidence: 85 },
    OSSig { name: "Alpine", version: "3.x", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[14600, 29200, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 0, sack: 1, keywords: &["alpine"], confidence: 85 },
    OSSig { name: "openSUSE", version: "Leap / Tumbleweed", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["opensuse","suse"], confidence: 88 },
    OSSig { name: "SUSE", version: "Enterprise", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 64240], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["suse enterprise","sles"], confidence: 88 },
    OSSig { name: "Kali Linux", version: "Rolling", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 64240, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["kali"], confidence: 90 },
    OSSig { name: "Linux Mint", version: "20-22", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[64240, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["mint","linuxmint"], confidence: 90 },
    OSSig { name: "Oracle Linux", version: "7-9", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[14600, 29200, 64240], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["oracle linux","unbreakable linux"], confidence: 88 },
    OSSig { name: "Amazon Linux", version: "2 / 2023", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["amazon linux"], confidence: 88 },
    // ─── macOS ────────────────────────────────────────────────────
    OSSig { name: "macOS", version: "10.x (Leopard-Mojave)", family: "macOS", ttl_min: 64, ttl_max: 64, window_sizes: &[65535], mss: 1460, wscale: 3, df: 1, timestamps: 1, sack: 1, keywords: &["darwin","mac os","macos"], confidence: 88 },
    OSSig { name: "macOS", version: "10.15 Catalina", family: "macOS", ttl_min: 64, ttl_max: 64, window_sizes: &[65535], mss: 1440, wscale: 3, df: 1, timestamps: 1, sack: 1, keywords: &["catalina","darwin"], confidence: 90 },
    OSSig { name: "macOS", version: "11 Big Sur", family: "macOS", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072], mss: 1440, wscale: 3, df: 1, timestamps: 1, sack: 1, keywords: &["big sur","darwin"], confidence: 90 },
    OSSig { name: "macOS", version: "12 Monterey", family: "macOS", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072], mss: 1380, wscale: 3, df: 1, timestamps: 1, sack: 1, keywords: &["monterey","darwin"], confidence: 90 },
    OSSig { name: "macOS", version: "13 Ventura", family: "macOS", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072], mss: 1360, wscale: 3, df: 1, timestamps: 1, sack: 1, keywords: &["ventura","darwin"], confidence: 90 },
    OSSig { name: "macOS", version: "14 Sonoma+", family: "macOS", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072, 262144], mss: 1360, wscale: 3, df: 1, timestamps: 1, sack: 1, keywords: &["sonoma","darwin"], confidence: 92 },
    OSSig { name: "iOS / iPadOS", version: "16-18", family: "iOS", ttl_min: 64, ttl_max: 64, window_sizes: &[65535], mss: 1380, wscale: 3, df: 1, timestamps: 1, sack: 1, keywords: &[], confidence: 85 },
    // ─── BSD ──────────────────────────────────────────────────────
    OSSig { name: "FreeBSD", version: "11.x", family: "BSD", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["freebsd"], confidence: 88 },
    OSSig { name: "FreeBSD", version: "12.x", family: "BSD", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["freebsd"], confidence: 90 },
    OSSig { name: "FreeBSD", version: "13.x-14.x", family: "BSD", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072], mss: 1460, wscale: 7, df: 1, timestamps: 0, sack: 1, keywords: &["freebsd"], confidence: 90 },
    OSSig { name: "OpenBSD", version: "6.x-7.x", family: "BSD", ttl_min: 64, ttl_max: 64, window_sizes: &[16384, 32768], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["openbsd"], confidence: 90 },
    OSSig { name: "NetBSD", version: "9.x-10.x", family: "BSD", ttl_min: 64, ttl_max: 64, window_sizes: &[32768, 65535], mss: 1460, wscale: 0, df: 1, timestamps: 1, sack: 1, keywords: &["netbsd"], confidence: 85 },
    OSSig { name: "DragonFly BSD", version: "6.x", family: "BSD", ttl_min: 64, ttl_max: 64, window_sizes: &[65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["dragonfly"], confidence: 80 },
    OSSig { name: "pfSense / OPNsense", version: "2.x-24.x", family: "BSD", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 131072], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["pfsense","opnsense","freebsd"], confidence: 85 },
    // ─── NETWORK DEVICES ──────────────────────────────────────────
    OSSig { name: "Cisco IOS", version: "12.x", family: "Network Device", ttl_min: 255, ttl_max: 255, window_sizes: &[4128, 65535], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["cisco ios"], confidence: 88 },
    OSSig { name: "Cisco IOS", version: "15.x", family: "Network Device", ttl_min: 255, ttl_max: 255, window_sizes: &[4128, 16384, 65535], mss: 1460, wscale: 3, df: 1, timestamps: 1, sack: 1, keywords: &["cisco ios"], confidence: 90 },
    OSSig { name: "Cisco IOS-XE", version: "16.x-17.x", family: "Network Device", ttl_min: 255, ttl_max: 255, window_sizes: &[16384, 65535], mss: 1460, wscale: 3, df: 1, timestamps: 1, sack: 1, keywords: &["ios-xe"], confidence: 90 },
    OSSig { name: "Cisco NX-OS", version: "7.x-10.x", family: "Network Device", ttl_min: 255, ttl_max: 255, window_sizes: &[65535, 4128], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["nx-os","nexus"], confidence: 85 },
    OSSig { name: "Cisco ASA", version: "8.x-9.x", family: "Network Device", ttl_min: 64, ttl_max: 255, window_sizes: &[8192, 4128, 65535], mss: 1380, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["cisco asa"], confidence: 88 },
    OSSig { name: "Juniper JunOS", version: "15.x-24.x", family: "Network Device", ttl_min: 64, ttl_max: 255, window_sizes: &[65535, 16384], mss: 1460, wscale: 0, df: 1, timestamps: 1, sack: 1, keywords: &["junos","juniper"], confidence: 90 },
    OSSig { name: "MikroTik RouterOS", version: "6.x-7.x", family: "Network Device", ttl_min: 64, ttl_max: 255, window_sizes: &[16384, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["mikrotik","routeros"], confidence: 90 },
    OSSig { name: "Fortinet FortiOS", version: "6.x-7.x", family: "Network Device", ttl_min: 255, ttl_max: 255, window_sizes: &[65535, 24240], mss: 1460, wscale: 2, df: 1, timestamps: 0, sack: 1, keywords: &["fortinet","fortios","fortigate"], confidence: 90 },
    OSSig { name: "PaloAlto PAN-OS", version: "8.x-11.x", family: "Network Device", ttl_min: 255, ttl_max: 255, window_sizes: &[65535, 16384], mss: 1460, wscale: 1, df: 1, timestamps: 1, sack: 1, keywords: &["pan-os","paloalto"], confidence: 85 },
    OSSig { name: "Ubiquiti UniFi", version: "6.x-8.x", family: "Network Device", ttl_min: 64, ttl_max: 255, window_sizes: &[29200, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["unifi","ubiquiti"], confidence: 85 },
    OSSig { name: "HP / Aruba", version: "ProCurve / AOS", family: "Network Device", ttl_min: 255, ttl_max: 255, window_sizes: &[65535, 16384], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["procurve","aruba","hp switch"], confidence: 80 },
    OSSig { name: "Zyxel", version: "Firmware", family: "Network Device", ttl_min: 64, ttl_max: 255, window_sizes: &[65535, 16384], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["zyxel"], confidence: 75 },
    // ─── ENTERPRISE UNIX ──────────────────────────────────────────
    OSSig { name: "Solaris", version: "10", family: "Unix", ttl_min: 255, ttl_max: 255, window_sizes: &[24820, 32850, 65535], mss: 1460, wscale: 0, df: 1, timestamps: 1, sack: 1, keywords: &["solaris","sunos"], confidence: 85 },
    OSSig { name: "Solaris", version: "11", family: "Unix", ttl_min: 255, ttl_max: 255, window_sizes: &[10648, 65535], mss: 1460, wscale: 0, df: 1, timestamps: 1, sack: 1, keywords: &["solaris","sunos"], confidence: 85 },
    OSSig { name: "AIX", version: "6.1-7.3", family: "Unix", ttl_min: 64, ttl_max: 255, window_sizes: &[16384, 32768, 65535], mss: 1440, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["aix","ibm"], confidence: 82 },
    OSSig { name: "HP-UX", version: "11i", family: "Unix", ttl_min: 255, ttl_max: 255, window_sizes: &[32768, 65535], mss: 1460, wscale: 0, df: 0, timestamps: 0, sack: 0, keywords: &["hp-ux","hpux"], confidence: 80 },
    // ─── CONTAINERS / CLOUD ───────────────────────────────────────
    OSSig { name: "Linux", version: "Docker Container", family: "Container", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 29200], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["docker","container"], confidence: 75 },
    OSSig { name: "Linux", version: "Kubernetes Node", family: "Container", ttl_min: 64, ttl_max: 64, window_sizes: &[29200, 65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["kubernetes","k8s"], confidence: 80 },
    OSSig { name: "Container-Optimized OS", version: "Cos", family: "Container", ttl_min: 64, ttl_max: 64, window_sizes: &[65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["cos","container-optimized"], confidence: 82 },
    // ─── HYPERVISORS ──────────────────────────────────────────────
    OSSig { name: "VMware ESXi", version: "5.x", family: "Hypervisor", ttl_min: 64, ttl_max: 255, window_sizes: &[65535, 16384], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["esxi","vmware"], confidence: 85 },
    OSSig { name: "VMware ESXi", version: "6.x", family: "Hypervisor", ttl_min: 64, ttl_max: 255, window_sizes: &[65535, 16384], mss: 1460, wscale: 0, df: 1, timestamps: 1, sack: 1, keywords: &["esxi","vmware"], confidence: 88 },
    OSSig { name: "VMware ESXi", version: "7.x-8.x", family: "Hypervisor", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 16384], mss: 1460, wscale: 0, df: 1, timestamps: 1, sack: 1, keywords: &["esxi","vmware"], confidence: 90 },
    OSSig { name: "Citrix Hypervisor / XCP-ng", version: "8.x", family: "Hypervisor", ttl_min: 64, ttl_max: 64, window_sizes: &[65535], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["xenserver","xcp-ng","citrix hypervisor"], confidence: 85 },
    OSSig { name: "Proxmox VE", version: "7.x-8.x", family: "Hypervisor", ttl_min: 64, ttl_max: 64, window_sizes: &[65535, 29200], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["proxmox","pve"], confidence: 85 },
    OSSig { name: "Microsoft Hyper-V", version: "Server", family: "Hypervisor", ttl_min: 128, ttl_max: 128, window_sizes: &[64240, 8192], mss: 1460, wscale: 8, df: 1, timestamps: 1, sack: 1, keywords: &["hyper-v"], confidence: 88 },
    // ─── EMBEDDED / IoT ──────────────────────────────────────────
    OSSig { name: "OpenWrt", version: "19.x-24.x", family: "Embedded", ttl_min: 64, ttl_max: 64, window_sizes: &[5840, 14600, 65535], mss: 1460, wscale: 2, df: 1, timestamps: 0, sack: 0, keywords: &["openwrt","lede"], confidence: 85 },
    OSSig { name: "DD-WRT", version: "Firmware", family: "Embedded", ttl_min: 64, ttl_max: 64, window_sizes: &[5840, 14600], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["dd-wrt","ddwrt"], confidence: 80 },
    OSSig { name: "VxWorks", version: "6.x-7.x", family: "Embedded", ttl_min: 64, ttl_max: 255, window_sizes: &[8760, 16384], mss: 1460, wscale: 0, df: 0, timestamps: 0, sack: 0, keywords: &["vxworks","wind river"], confidence: 75 },
    OSSig { name: "Android", version: "10-15", family: "Mobile", ttl_min: 64, ttl_max: 64, window_sizes: &[5840, 16384, 29200], mss: 1460, wscale: 7, df: 1, timestamps: 1, sack: 1, keywords: &["android"], confidence: 85 },
    OSSig { name: "Samsung SmartThings / Hub", version: "Embedded", family: "Embedded", ttl_min: 64, ttl_max: 255, window_sizes: &[5840, 14600], mss: 1460, wscale: 0, df: 1, timestamps: 0, sack: 0, keywords: &["smartthings","samsung"], confidence: 65 },
    // ─── OTHER / GENERIC ──────────────────────────────────────────
    OSSig { name: "Generic", version: "Unix/Linux", family: "Linux", ttl_min: 64, ttl_max: 64, window_sizes: &[5840, 5792, 29200, 64240, 65535, 32736, 131072, 262144], mss: 1460, wscale: -1, df: 1, timestamps: -1, sack: -1, keywords: &["linux","unix"], confidence: 60 },
    OSSig { name: "Generic", version: "Windows", family: "Windows", ttl_min: 128, ttl_max: 128, window_sizes: &[8192, 65535, 64240, 16384, 17520], mss: 1460, wscale: -1, df: 1, timestamps: -1, sack: -1, keywords: &["windows","win32","win64","microsoft"], confidence: 60 },
    OSSig { name: "Generic", version: "Network Device", family: "Network Device", ttl_min: 255, ttl_max: 255, window_sizes: &[4128, 16384, 65535, 512, 24240], mss: 1460, wscale: -1, df: -1, timestamps: -1, sack: -1, keywords: &[], confidence: 50 },
];

fn extract_tcp_params(banner: &str) -> (i32, i8, bool, bool, bool, String) {
    let mut mss: i32 = 0;
    let mut wscale: i8 = -1;
    let mut df: bool = true;
    let mut ts: bool = false;
    let mut sack: bool = true;
    let clean: &str;
    if let Some(pipe) = banner.rfind('|') {
        let tail = &banner[pipe + 1..];
        clean = &banner[..pipe];
        for tok in tail.split_whitespace() {
            if let Some(v) = tok.strip_prefix("MSS=") { mss = v.parse().unwrap_or(0); }
            else if let Some(v) = tok.strip_prefix("WS=") { wscale = v.parse().unwrap_or(-1); }
            else if let Some(v) = tok.strip_prefix("DF=") { df = v == "1"; }
            else if let Some(v) = tok.strip_prefix("TS=") { ts = v == "1"; }
            else if let Some(v) = tok.strip_prefix("SACK=") { sack = v == "1"; }
        }
    } else {
        clean = banner;
    }
    (mss, wscale, df, ts, sack, clean.to_string())
}

fn score_fingerprint(fp: &OSSig, ttl: i32, win: i32, mss: i32, wscale: i8, df: bool, ts: bool, sack: bool, b_lower: &str) -> i32 {
    let mut score = 0i32;
    if ttl >= fp.ttl_min && ttl <= fp.ttl_max {
        score += 25;
        if ttl == 64 || ttl == 128 || ttl == 255 { score += 5; }
    }
    for &w in fp.window_sizes {
        if win == w { score += 20; break; }
        if win > 0 && w > 0 && (win - w).abs() <= 1024 { score += 10; break; }
    }
    if fp.mss > 0 && mss > 0 {
        if mss == fp.mss { score += 15; }
        else if (mss - fp.mss).abs() <= 100 { score += 8; }
    }
    if fp.wscale >= 0 && wscale >= 0 && wscale == fp.wscale { score += 10; }
    if fp.df >= 0 && (fp.df == 1) == df { score += 8; }
    if fp.timestamps >= 0 && (fp.timestamps == 1) == ts { score += 8; }
    if fp.sack >= 0 && (fp.sack == 1) == sack { score += 8; }
    for kw in fp.keywords {
        if !kw.is_empty() && b_lower.contains(kw) { score += 20; }
    }
    score
}

fn extract_version_from_ssh(banner: &str) -> Option<String> {
    let b = banner.to_lowercase();
    if !b.contains("ssh-2.0-") && !b.contains("openssh") {
        return None;
    }
    let ubuntu_ssh = [
        ("8.9", "22.04 LTS"), ("8.4", "20.04 LTS"), ("7.6", "18.04 LTS"),
        ("7.2", "16.04 LTS"), ("6.6", "14.04 LTS"), ("6.0", "12.04 LTS"),
        ("5.9", "10.04 LTS"), ("9.3", "24.04 LTS"), ("9.6", "25.04"),
    ];
    let debian_ssh = [
        ("9.2", "13 (Trixie)"), ("9.0", "12 (Bookworm)"), ("8.4", "11 (Bullseye)"),
        ("7.9", "10 (Buster)"), ("7.4", "9 (Stretch)"), ("6.7", "8 (Jessie)"),
        ("5.9", "7 (Wheezy)"),
    ];
    let centos_ssh = [("8.0", "8"), ("7.4", "7"), ("6.6", "6")];
    let fedora_ssh = [("8.4", "33-38"), ("7.6", "28-32"), ("9.3", "39-40")];
    let freebsd_ssh = [("8.9", "13.x-14.x"), ("7.9", "12.x"), ("7.4", "11.x")];
    if b.contains("ubuntu") {
        for &(ver, osv) in &ubuntu_ssh {
            if b.contains(ver) { return Some(format!("Ubuntu {}", osv)); }
        }
        return Some("Ubuntu LTS (generic)".into());
    }
    if b.contains("debian") {
        for &(ver, osv) in &debian_ssh {
            if b.contains(ver) { return Some(format!("Debian {}", osv)); }
        }
        return Some("Debian GNU/Linux".into());
    }
    if b.contains("centos") || b.contains("rhel") {
        for &(ver, osv) in &centos_ssh {
            if b.contains(ver) { return Some(format!("CentOS/RHEL {}", osv)); }
        }
        return Some("Enterprise Linux".into());
    }
    if b.contains("fedora") {
        for &(ver, osv) in &fedora_ssh {
            if b.contains(ver) { return Some(format!("Fedora {}", osv)); }
        }
        return Some("Fedora Linux".into());
    }
    if b.contains("freebsd") {
        for &(ver, osv) in &freebsd_ssh {
            if b.contains(ver) { return Some(format!("FreeBSD {}", osv)); }
        }
        return Some("FreeBSD".into());
    }
    if b.contains("darwin") || b.contains("mac") {
        return Some("macOS (from SSH)".into());
    }
    None
}

fn extract_version_from_http(banner: &str) -> Option<String> {
    let b_lower = banner.to_lowercase();
    for line in b_lower.lines() {
        let line = line.trim();
        if !line.starts_with("server:") { continue; }
        let val = line["server:".len()..].trim();
        if val.contains("microsoft-iis/10") { return Some("Windows Server 2016/2019/2022".into()); }
        if val.contains("microsoft-iis/8.5") { return Some("Windows Server 2012 R2".into()); }
        if val.contains("microsoft-iis/8.0") { return Some("Windows Server 2012".into()); }
        if val.contains("microsoft-iis/7.5") { return Some("Windows Server 2008 R2".into()); }
        if val.contains("microsoft-iis/7.0") { return Some("Windows Server 2008".into()); }
        if val.contains("microsoft-iis/6.0") { return Some("Windows Server 2003".into()); }
        if val.contains("ubuntu") { return Some("Ubuntu".into()); }
        if val.contains("debian") { return Some("Debian".into()); }
        if val.contains("centos") { return Some("CentOS".into()); }
    }
    None
}

fn extract_version_from_ftp(banner: &str) -> Option<String> {
    let b = banner.to_lowercase();
    if b.contains("ubuntu") { return Some("Ubuntu (FTP)".into()); }
    if b.contains("debian") { return Some("Debian (FTP)".into()); }
    if b.contains("centos") { return Some("CentOS (FTP)".into()); }
    if b.contains("freebsd") { return Some("FreeBSD (FTP)".into()); }
    if b.contains("microsoft ftp") || b.contains("microsoft-ftp") { return Some("Windows Server IIS FTP".into()); }
    None
}

fn extract_os_version(banner: &str) -> (String, String) {
    if let Some(v) = extract_version_from_ssh(banner) { return ("SSH Fingerprint".into(), v); }
    if let Some(v) = extract_version_from_http(banner) { return ("HTTP Server OS".into(), v); }
    if let Some(v) = extract_version_from_ftp(banner) { return ("FTP Server OS".into(), v); }
    ("Unknown".into(), "Unknown".into())
}

/// Core detection function: scores observed TCP parameters and banner text against 80+ OS signatures.
pub fn detect_os_from_tcp_params(ttl: i32, window_size: i32, banner: &str) -> RustOSInfo {
    let (mss, wscale, df, ts, sack, clean_banner) = extract_tcp_params(banner);
    let b_lower = clean_banner.to_lowercase();
    let mut best_score = 0i32;
    let mut best_fp: Option<&OSSig> = None;
    for fp in OS_FP.iter() {
        let s = score_fingerprint(fp, ttl, window_size, mss, wscale, df, ts, sack, &b_lower);
        if s > best_score {
            best_score = s;
            best_fp = Some(fp);
        }
    }
    let mut os_name = "Unknown";
    let mut os_version = "Unknown";
    let mut os_family = "Unknown";
    let mut accuracy = 30i32;
    let mut evidence: Vec<String> = Vec::new();
    if let Some(fp) = best_fp {
        let raw = best_score.min(100);
        accuracy = raw.max(fp.confidence as i32 - 5).min(100);
        os_name = fp.name;
        os_version = fp.version;
        os_family = fp.family;
        evidence.push(format!("fp: TTL={}, WIN={}, MSS={}, WS={}, DF={}, TS={}, SACK={} => {} {} (score={})",
            ttl, window_size, mss, wscale, df as i32, ts as i32, sack as i32, fp.name, fp.version, best_score));
        for kw in fp.keywords {
            if !kw.is_empty() && b_lower.contains(kw) {
                evidence.push(format!("banner keyword match: '{}'", kw));
            }
        }
    }
    // Banner-only override (higher accuracy)
    if b_lower.contains("ubuntu") {
        let ver = if b_lower.contains("24.04") { "24.04 LTS" } else if b_lower.contains("22.04") { "22.04 LTS" }
        else if b_lower.contains("20.04") { "20.04 LTS" } else if b_lower.contains("18.04") { "18.04 LTS" }
        else if b_lower.contains("16.04") { "16.04 LTS" } else { "Ubuntu LTS" };
        if accuracy < 95 { os_name = "Ubuntu"; os_family = "Linux"; os_version = ver; accuracy = 95; }
        evidence.push("banner=ubuntu".to_string());
    }
    if b_lower.contains("debian") {
        let ver = if b_lower.contains("bookworm") { "12 (Bookworm)" } else if b_lower.contains("bullseye") { "11 (Bullseye)" }
        else if b_lower.contains("buster") { "10 (Buster)" } else { "Debian GNU/Linux" };
        if accuracy < 93 { os_name = "Debian"; os_family = "Linux"; os_version = ver; accuracy = 93; }
        evidence.push("banner=debian".to_string());
    }
    // Version extraction from service banners
    let (v_name, v_ver) = extract_os_version(&clean_banner);
    if v_name != "Unknown" {
        if accuracy < 88 { accuracy = 88; }
        evidence.push(format!("version extraction: {} ({})", v_name, v_ver));
    }
    // Docker / container override
    if b_lower.contains("docker") || b_lower.contains("kubernetes") {
        if !os_name.contains("Container") && !os_name.contains("Kubernetes") && !os_name.contains("Docker") {
            let container_os = if b_lower.contains("kubernetes") { "Linux (Kubernetes)" } else { "Linux (Docker Container)" };
            os_name = container_os; os_family = "Container";
            if accuracy < 80 { accuracy = 80; }
            evidence.push("container indicator detected".to_string());
        }
    }
    if ttl <= 64 && b_lower.contains("lighttpd") && !b_lower.contains("ubuntu") && !b_lower.contains("debian") && !b_lower.contains("centos") {
        if !os_name.contains("Alpine") { os_name = "Alpine Linux"; os_family = "Linux"; os_version = "3.x"; accuracy = accuracy.max(75); evidence.push("ttl<=64 + lighttpd => Alpine".to_string()); }
    }
    if ttl > 0 { evidence.push(format!("observed ttl={}", ttl)); }
    if window_size > 0 { evidence.push(format!("observed window={}", window_size)); }
    if mss > 0 { evidence.push(format!("observed mss={}", mss)); }
    let evidence_str = evidence.join("; ");
    RustOSInfo {
        os_name: CString::new(os_name).unwrap().into_raw(),
        os_version: CString::new(os_version).unwrap().into_raw(),
        os_family: CString::new(os_family).unwrap().into_raw(),
        accuracy: accuracy.min(100),
        ttl,
        window_size,
        evidence: CString::new(evidence_str).unwrap().into_raw(),
    }
}

/// Measure TTL via `ping` command.
pub fn measure_ttl(host: &str) -> i32 {
    if let Ok(out) = Command::new("ping").args(["-c", "1", "-W", "2", host]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if line.contains("ttl=") {
                if let Some(pos) = line.find("ttl=") {
                    let rest: String = line[pos + 4..].chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(ttl) = rest.parse::<i32>() { return ttl; }
                }
            }
        }
    }
    0
}

/// Connect to target port, send protocol probe, read banner.
pub fn probe_banner(host: &str, port: u16, timeout_ms: u64) -> String {
    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_millis(timeout_ms);
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap_or(addr.parse().unwrap()), timeout) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms / 2)));
        let probe = match port {
            22 => "SSH-2.0-HackIT\r\n",
            80 | 443 | 8080 | 8443 => "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            21 => "SYST\r\n",
            25 | 587 => "EHLO localhost\r\n",
            110 => "CAPA\r\n",
            143 => "A001 CAPABILITY\r\n",
            3306 => "",
            5432 => "",
            6379 => "PING\r\n",
            27017 => "",
            _ => "\r\n",
        }.to_string();
        if !probe.is_empty() {
            let _ = stream.write_all(probe.as_bytes());
            let _ = stream.flush();
        }
        let mut buf = [0u8; 4096];
        if let Ok(n) = stream.read(&mut buf) {
            if n > 0 {
                return String::from_utf8_lossy(&buf[..n]).to_string();
            }
        }
    }
    String::new()
}

/// Full probe + detect pipeline: measures TTL, probes common ports, detects OS.
pub fn probe_and_detect_os(host: &str, ports: &[u16], timeout_ms: u64) -> RustOSInfo {
    let mut best: Option<RustOSInfo> = None;
    let ttl = measure_ttl(host);
    for &port in ports.iter() {
        let banner = probe_banner(host, port, timeout_ms);
        if !banner.is_empty() {
            let info = detect_os_from_tcp_params(ttl, 0, &banner);
            if info.accuracy > best.as_ref().map_or(0, |b| b.accuracy) {
                // free old best
                if let Some(old) = best.take() {
                    let _ = unsafe { CString::from_raw(old.os_name) };
                    let _ = unsafe { CString::from_raw(old.os_version) };
                    let _ = unsafe { CString::from_raw(old.os_family) };
                    let _ = unsafe { CString::from_raw(old.evidence) };
                }
                best = Some(info);
            } else {
                let _ = unsafe { CString::from_raw(info.os_name) };
                let _ = unsafe { CString::from_raw(info.os_version) };
                let _ = unsafe { CString::from_raw(info.os_family) };
                let _ = unsafe { CString::from_raw(info.evidence) };
            }
        }
    }
    match best {
        Some(info) => info,
        None => detect_os_from_tcp_params(ttl, 0, ""),
    }
}

// ─── C FFI ──────────────────────────────────────────────────────────
/// FFI: OS detection from pre-collected parameters.
/// Host string is accepted for compatibility but not used for internal probing.
/// Banner may contain embedded TCP options: "banner_text|MSS=1460 WS=7 DF=1 TS=1 SACK=1"
#[no_mangle]
pub unsafe extern "C" fn rust_detect_os(
    host: *const c_char,
    banner_sample: *const c_char,
    ttl: i32,
    window_size: i32,
) -> *mut RustOSInfo {
    let _c_host = CStr::from_ptr(host).to_str().unwrap_or("");
    let c_banner = CStr::from_ptr(banner_sample).to_str().unwrap_or("");
    let info = detect_os_from_tcp_params(ttl, window_size, c_banner);
    Box::into_raw(Box::new(info))
}

/// FFI: Full probe-and-detect. Ports are comma-separated, e.g. "22,80,443,21".
/// Returns RustOSInfo as pointer.
#[no_mangle]
pub unsafe extern "C" fn rust_probe_and_detect_os(
    host: *const c_char,
    ports_str: *const c_char,
    timeout_ms: i32,
) -> *mut RustOSInfo {
    let host_s = CStr::from_ptr(host).to_str().unwrap_or("");
    let ports_s = CStr::from_ptr(ports_str).to_str().unwrap_or("22,80,443");
    let ports: Vec<u16> = ports_s.split(',').filter_map(|p| p.trim().parse().ok()).collect();
    let timeout = if timeout_ms > 0 { timeout_ms as u64 } else { 1500 };
    let info = probe_and_detect_os(host_s, &ports, timeout);
    Box::into_raw(Box::new(info))
}

/// FFI: Measure TTL via ping.
#[no_mangle]
pub unsafe extern "C" fn rust_measure_ttl(host: *const c_char) -> i32 {
    let host_s = CStr::from_ptr(host).to_str().unwrap_or("");
    measure_ttl(host_s)
}

/// FFI: Free a RustOSInfo pointer.
#[no_mangle]
pub unsafe extern "C" fn rust_free_os_info(ptr: *mut RustOSInfo) {
    if ptr.is_null() { return; }
    let info = Box::from_raw(ptr);
    let _ = CString::from_raw(info.os_name);
    let _ = CString::from_raw(info.os_version);
    let _ = CString::from_raw(info.os_family);
    let _ = CString::from_raw(info.evidence);
}

/// FFI: Extract OS version string from banner (text output).
#[no_mangle]
pub unsafe extern "C" fn rust_extract_os_version(banner: *const c_char) -> *mut c_char {
    let c_banner = CStr::from_ptr(banner).to_str().unwrap_or("");
    let (source, version) = extract_os_version(c_banner);
    if source == "Unknown" {
        return CString::new("UNKNOWN").unwrap().into_raw();
    }
    let result = format!("{}: {}", source, version);
    CString::new(result).unwrap().into_raw()
}
