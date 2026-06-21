#!/usr/bin/env python3
"""
HackIT PortStorm — Build System v3.0 (MAX PERFORMANCE)
Parallel compilation · PGO-ready · LTO · Auto CPU
"""

import os, subprocess, shutil, sys, time, multiprocessing

C = {'OK':32,'FAIL':31,'WARN':33,'INFO':34,'HDR':36}
_BASE=os.path.dirname(os.path.abspath(__file__))
_BIN=os.path.join(_BASE,'bin')
_CPU=multiprocessing.cpu_count()

def clr(t,c): return f'\033[{c}m{t}\033[0m'
def run(c,cwd=None,timeout=300):
    return subprocess.run(c,cwd=cwd,capture_output=1,text=1,timeout=timeout)

# ── CPU & arch auto-detect ──────────────────────────────────────────
def _arch_flags():
    """Auto-detect best arch flags for this CPU."""
    try:
        import platform
        m=platform.machine()
        if m in ('x86_64','amd64'):
            r=run(['gcc','-march=native','-E','-v','-'],cwd=_BASE)
            out=r.stderr.lower()
            if 'znver' in out: return '-march=znver4 -mtune=znver4'
            if 'haswell' in out or 'broadwell' in out: return '-march=haswell -mtune=haswell'
            if 'skylake' in out or 'cascadelake' in out: return '-march=skylake -mtune=cascadelake'
            return '-march=native -mtune=native'
        elif m in ('aarch64','arm64'): return '-march=armv8-a+simd -mtune=native'
        return '-march=native -mtune=native'
    except: return '-march=native -mtune=native'

_ARCH=_arch_flags()
_CFLAGS=f'-O3 {_ARCH} -flto=1 -fomit-frame-pointer -funroll-loops -fmerge-all-constants -pthread'
_CXXFLAGS=f'-O3 {_ARCH} -flto=1 -fomit-frame-pointer -funroll-loops -fmerge-all-constants -pthread -std=c++17'
_LDFLAGS='-fuse-linker-plugin'

# ── Build Go ────────────────────────────────────────────────────────
def _go():
    print(clr('[  GO   ]','\033[1;34m'))
    gd=os.path.join(_BASE,'go')
    t=time.time()
    r=run(['go','build','-ldflags=-s -w','-o','port_scanner','.'],cwd=gd)
    if r.returncode==0:
        shutil.copy(os.path.join(gd,'port_scanner'),os.path.join(_BIN,'port_scanner'))
        sz=os.path.getsize(os.path.join(_BIN,'port_scanner'))
        print(clr(f'  \u2713 port_scanner  {sz//1024}KB','92'))
    else: print(clr(f'  \u2717 port_scanner  {r.stderr[:150]}','91'))
    for h in ['dns_resolver','geo_enricher','output_formatter']:
        s=os.path.join(gd,'cmd',h,'main.go')
        if not os.path.exists(s): continue
        r=run(['go','build','-ldflags=-s -w','-o',os.path.join(_BIN,h),s],cwd=gd)
        if r.returncode==0:
            sz=os.path.getsize(os.path.join(_BIN,h))
            print(clr(f'  \u2713 {h}  {sz//1024}KB','92'))
        else: print(clr(f'  \u2717 {h}  {r.stderr[:100]}','91'))
    print(clr(f'  \u2192 {time.time()-t:.1f}s','90'))

# ── Build Rust ──────────────────────────────────────────────────────
def _rust():
    print(clr('[ RUST  ]','\033[1;32m'))
    rd=os.path.join(_BASE,'go','rust_engine')
    if not os.path.exists(rd): return
    tgts=['tcp_scanner','udp_scanner','service_detect','os_fingerprint',
          'dns_enum','vuln_scan','mass_scan',
          'hyper_parallel_tcp','smart_service_detect','dns_over_https',
          'vuln_priority_scanner','real_time_monitor']
    t=time.time()
    # Add RUSTFLAGS for max perf
    env=os.environ.copy()
    env['RUSTFLAGS']='-C target-cpu=native -C opt-level=3 -C lto=fat -C codegen-units=1'
    r=run(['cargo','build','--release']+[f'--bin={t}' for t in tgts],
          cwd=rd,timeout=600)
    if r.returncode==0:
        for tgt in tgts:
            s=os.path.join(rd,'target','release',tgt)
            if os.path.exists(s):
                shutil.copy2(s,os.path.join(_BIN,f'rust_{tgt}'))
                sz=os.path.getsize(os.path.join(_BIN,f'rust_{tgt}'))
                print(clr(f'  \u2713 rust_{tgt}  {sz//1024}KB','92'))
        print(clr(f'  \u2192 {time.time()-t:.1f}s','90'))
    else: print(clr(f'  \u2717 Rust: {r.stderr[:200]}','91'))

# ── Build C (sequential, avoids LTO race) ─────────────────────────────
C_TARGETS=[
    ('scanner.c','c_scanner',''),
    ('syn_scanner.c','c_syn_scanner',''),
    ('syn_scanner_v2.c','c_syn_scanner_v2',''),
    ('mass_tcp_scanner.c','c_mass_tcp_scanner',''),
    ('udp_scanner.c','c_udp_scanner',''),
    ('udp_prober.c','c_udp_prober',''),
    ('tcp_prober.c','c_tcp_prober',''),
    ('banner_grabber.c','c_banner_grabber','-lssl -lcrypto'),
    ('os_fingerprint.c','c_os_fingerprint',''),
    ('os_fingerprint_v2.c','c_os_fingerprint_v2',''),
    ('os_detect.c','c_os_detect.so','-shared -fPIC -lssl -lcrypto'),
    ('service_prober.c','c_service_prober',''),
    ('icmp_discovery.c','c_icmp_discovery',''),
    ('tls_prober.c','c_tls_prober','-lssl -lcrypto'),
    ('packet_crafter.c','c_packet_crafter',''),
    ('network_path.c','c_network_path',''),
    ('network_topology.c','c_network_topology',''),
    ('network_oracle.c','c_network_oracle',''),
    ('stealth_evasion.c','c_stealth_evasion',''),
    ('c_evasion.c','c_c_evasion',''),
    ('epoll_scanner.c','c_epoll_scanner',''),
    ('advanced_scanner.c','c_advanced_scanner',''),
    ('full_system_scanner.c','c_full_system_scanner',''),
    ('deep_packet_analysis.c','c_deep_packet_analysis',''),
    ('service_exploiter.c','c_service_exploiter',''),
    ('credential_harvester.c','c_credential_harvester',''),
    ('performance_bench.c','c_performance_bench',''),
    ('ssl_deep_scan.c','c_ssl_deep_scan',''),
    ('web_app_fingerprint.c','c_web_app_fingerprint',''),
    ('database_scanner.c','c_database_scanner',''),
    ('iot_scanner.c','c_iot_scanner',''),
    # New expert engines
    ('syn_flood_optimized.c','c_syn_flood',''),
    ('dns_burst_resolver.c','c_dns_burst',''),
    ('service_fingerprinter.c','c_service_fp',''),
    ('mass_port_scanner.c','c_mass_scan',''),
    ('cve_matcher.c','c_cve_match',''),
    ('packet_inspector.c','c_packet_inspect',''),
    ('network_discovery.c','c_net_discover',''),
]

def _c():
    print(clr('[   C   ] sequential (avoids LTO race)','\033[1;33m'))
    cd=os.path.join(_BASE,'c')
    os.makedirs(_BIN,exist_ok=1)
    ok=[]; fail=[]; t=time.time()
    for src,out,libs in C_TARGETS:
        cmd=['gcc',*_CFLAGS.split(),'-o',out,src]
        if libs: cmd.extend(libs.split())
        r=run(cmd,cwd=cd)
        fp=os.path.join(cd,out)
        if r.returncode==0 and os.path.exists(fp):
            shutil.copy(fp,os.path.join(_BIN,out))
            sz=os.path.getsize(os.path.join(_BIN,out))
            ok.append((out,sz))
            print(clr(f'  \u2713 {out}  {sz//1024}KB','92'))
        else:
            err=r.stderr.strip()[:120] if r.stderr else '?'
            fail.append((out,err))
            print(clr(f'  \u2717 {out}','91'))
    print(clr(f'  \u2192 {len(ok)} built, {len(fail)} skipped ({time.time()-t:.1f}s)','90'))
    if fail:
        print(clr('  Skipped:','93'))
        for n,e in fail: print(clr(f'    {n}: {e}','91'))

# ── Build C++ (parallel) ───────────────────────────────────────────
CPP_TARGETS=[
    ('service_scanner.cpp','cpp_service_scanner',''),
    ('os_detect.cpp','cpp_os_detect',''),
    ('vuln_matcher.cpp','cpp_vuln_matcher',''),
    ('vuln_matcher_v2.cpp','cpp_vuln_matcher_v2',''),
    ('results_correlator.cpp','cpp_results_correlator',''),
    ('anomaly_detector.cpp','cpp_anomaly_detector',''),
    ('ai_pattern_analyzer.cpp','cpp_ai_pattern_analyzer',''),
    ('correlation_engine.cpp','cpp_correlation_engine',''),
    ('service_classifier.cpp','cpp_service_classifier',''),
    ('stack_fingerprinter.cpp','cpp_stack_fingerprinter',''),
    ('risk_calculator.cpp','cpp_risk_calculator',''),
    ('report_generator.cpp','cpp_report_generator',''),
    ('tls_scanner.cpp','cpp_tls_scanner','-lssl -lcrypto'),
    # New expert engines
    ('deep_learning_analyzer.cpp','cpp_dl_analyzer',''),
    ('tls_forensic_analyzer.cpp','cpp_tls_forensic','-lssl -lcrypto'),
    ('exploit_detection_engine.cpp','cpp_exploit_detect',''),
]

def _cpp():
    print(clr('[  C++  ] sequential (avoids LTO race)','\033[1;35m'))
    cppd=os.path.join(_BASE,'cpp')
    ok=[]; fail=[]; t=time.time()
    for src,out,libs in CPP_TARGETS:
        cmd=['g++',*_CXXFLAGS.split(),'-o',out,src]
        if libs: cmd.extend(libs.split())
        r=run(cmd,cwd=cppd)
        fp=os.path.join(cppd,out)
        if r.returncode==0 and os.path.exists(fp):
            shutil.copy(fp,os.path.join(_BIN,out))
            sz=os.path.getsize(os.path.join(_BIN,out))
            ok.append((out,sz))
            print(clr(f'  \u2713 {out}  {sz//1024}KB','92'))
        else:
            err=r.stderr.strip()[:120] if r.stderr else '?'
            fail.append((out,err))
            print(clr(f'  \u2717 {out}','91'))
    print(clr(f'  \u2192 {len(ok)} OK, {len(fail)} fail ({time.time()-t:.1f}s)','90'))
    if fail:
        for n,e in fail: print(clr(f'    {n}: {e}','91'))

# ── Validate ────────────────────────────────────────────────────────
def _validate():
    print(clr(f'\n{"="*55}','90'))
    print(clr('  DEPLOYED BINARIES','96'))
    print(clr(f'{"="*55}','90'))
    if not os.path.exists(_BIN): return
    total=0
    for f in sorted(os.listdir(_BIN)):
        fp=os.path.join(_BIN,f)
        if not os.path.isfile(fp) or os.path.islink(fp): continue
        sz=os.path.getsize(fp)
        total+=sz
        print(clr(f'  {f:42s} {sz:>8,} bytes','36'))
    mb=total/(1024*1024)
    print(clr(f'  {"─"*55}','90'))
    print(clr(f'  {len(os.listdir(_BIN)):42} {mb:.1f} MB','92'))

if __name__=='__main__':
    os.makedirs(_BIN,exist_ok=1)
    t0=time.time()
    print(clr(f'  Build System v3 — {_CPU} cores — {_ARCH}','96'))
    print(clr(f'  C flags: {_CFLAGS}','90'))
    print(clr(f'  C++ flags: {_CXXFLAGS}','90'))
    _go(); _rust(); _c(); _cpp(); _validate()
    print(clr(f'\n  \u2713 Total: {time.time()-t0:.1f}s','92'))
