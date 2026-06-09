package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// ─────────────────────────────────────────────────────────────────
// LUA ENGINE v3.0 — NSE-style scripting with full socket API
// ─────────────────────────────────────────────────────────────────

type LuaEngine struct {
	ScriptsDir string
	LuaDir     string
}

func NewLuaEngine() *LuaEngine {
	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)

	// Try multiple possible locations for Lua scripts
	candidates := []string{
		filepath.Join(baseDir, "..", "lua"),
		filepath.Join(baseDir, "scripts"),
		filepath.Join("d:/web/hacks/hackstools/hackit/port_scanner/lua"),
	}

	luaDir := candidates[0]
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			luaDir = c
			break
		}
	}

	scriptsDir := filepath.Join(baseDir, "scripts")
	os.MkdirAll(scriptsDir, 0755)

	return &LuaEngine{
		ScriptsDir: scriptsDir,
		LuaDir:     luaDir,
	}
}

// RunScripts runs all applicable Lua scripts for the given port/service
func (e *LuaEngine) RunScripts(host string, port int, service string, banner string) []string {
	var results []string

	// 1. Run tactical vuln scanner (primary)
	vulnScript := filepath.Join(e.LuaDir, "tactical_vuln.lua")
	if _, err := os.Stat(vulnScript); err == nil {
		res, err := e.executeLuaVulnScan(vulnScript, host, port, service, banner)
		if err == nil && res != "" {
			for _, line := range strings.Split(res, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					results = append(results, line)
				}
			}
		}
	}

	// 2. Run precision probe
	probeScript := filepath.Join(e.LuaDir, "precision_probe.lua")
	if _, err := os.Stat(probeScript); err == nil {
		svc, ver := e.executePrecisionProbe(probeScript, host, port, banner)
		if svc != "" {
			results = append(results, fmt.Sprintf("[LUA-PROBE] Identified: %s %s", svc, ver))
		}
	}

	// 3. Run user-defined scripts from scripts dir
	files, err := os.ReadDir(e.ScriptsDir)
	if err == nil {
		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".lua") {
				continue
			}
			scriptPath := filepath.Join(e.ScriptsDir, file.Name())
			res, err := e.executeScript(scriptPath, host, port, service, banner)
			if err == nil && res != "" {
				results = append(results, fmt.Sprintf("[%s] %s", file.Name(), res))
			}
		}
	}

	return results
}

// LuaRunTactical is a legacy compatibility wrapper
func LuaRunTactical(host string, port int, mode string) string {
	engine := NewLuaEngine()
	banner := GrabBannerByHost(host, port, 1500)
	results := engine.RunScripts(host, port, "", banner)
	return strings.Join(results, "; ")
}

// executeLuaVulnScan runs the tactical_vuln.lua script
func (e *LuaEngine) executeLuaVulnScan(path, host string, port int, service, banner string) (string, error) {
	L := e.newState()
	defer L.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	L.SetContext(ctx)

	e.registerFunctions(L, host, port)
	L.SetGlobal("host", lua.LString(host))
	L.SetGlobal("port", lua.LNumber(port))
	L.SetGlobal("service", lua.LString(service))
	L.SetGlobal("banner", lua.LString(banner))

	if err := L.DoFile(path); err != nil {
		return "", err
	}

	// Call run_lua_vuln_scan(host, port, service, banner)
	fn := L.GetGlobal("run_lua_vuln_scan")
	if fn.Type() == lua.LTNil {
		// Try run_audit
		fn = L.GetGlobal("run_audit")
	}
	if fn.Type() == lua.LTNil {
		return "", nil
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	},
		lua.LString(host),
		lua.LNumber(port),
		lua.LString(service),
		lua.LString(banner),
	); err != nil {
		return "", err
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() == lua.LTString {
		return ret.String(), nil
	}
	return "", nil
}

// executePrecisionProbe runs the precision_probe.lua script
func (e *LuaEngine) executePrecisionProbe(path, host string, port int, banner string) (string, string) {
	L := e.newState()
	defer L.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	L.SetContext(ctx)

	if err := L.DoFile(path); err != nil {
		return "", ""
	}

	fn := L.GetGlobal("run_precision_probe")
	if fn.Type() == lua.LTNil {
		return "", ""
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    2,
		Protect: true,
	},
		lua.LString(host),
		lua.LNumber(port),
		lua.LString(banner),
	); err != nil {
		return "", ""
	}

	svc := L.Get(-2)
	ver := L.Get(-1)
	L.Pop(2)

	svcStr := ""
	verStr := ""
	if svc.Type() == lua.LTString {
		svcStr = svc.String()
	}
	if ver.Type() == lua.LTString {
		verStr = ver.String()
	}
	return svcStr, verStr
}

// executeScript runs a generic Lua script looking for an "action" function
func (e *LuaEngine) executeScript(path, host string, port int, service, banner string) (string, error) {
	L := e.newState()
	defer L.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	L.SetContext(ctx)

	e.registerFunctions(L, host, port)
	L.SetGlobal("host", lua.LString(host))
	L.SetGlobal("port", lua.LNumber(port))
	L.SetGlobal("service", lua.LString(service))
	L.SetGlobal("banner", lua.LString(banner))

	if err := L.DoFile(path); err != nil {
		return "", err
	}

	fn := L.GetGlobal("action")
	if fn.Type() == lua.LTNil {
		return "", nil
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}); err != nil {
		return "", err
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() == lua.LTString {
		return ret.String(), nil
	}
	return "", nil
}

// newState creates a sandboxed Lua state with safe libs
func (e *LuaEngine) newState() *lua.LState {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})

	for _, lib := range []struct {
		Name string
		Fn   lua.LGFunction
	}{
		{lua.LoadLibName, lua.OpenPackage},
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	} {
		L.CallByParam(lua.P{
			Fn:      L.NewFunction(lib.Fn),
			NRet:    0,
			Protect: true,
		}, lua.LString(lib.Name))
	}
	return L
}

// registerFunctions registers Go-backed functions for Lua scripts
func (e *LuaEngine) registerFunctions(L *lua.LState, host string, port int) {
	// connect(host, port, timeout_ms) → conn
	L.SetGlobal("connect", L.NewFunction(func(L *lua.LState) int {
		h := L.CheckString(1)
		p := L.CheckInt(2)
		timeout := L.OptInt(3, 2000)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, p),
			time.Duration(timeout)*time.Millisecond)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		ud := L.NewUserData()
		ud.Value = conn
		L.Push(ud)
		return 1
	}))

	// send(conn, data) → bool
	L.SetGlobal("send", L.NewFunction(func(L *lua.LState) int {
		ud := L.CheckUserData(1)
		data := L.CheckString(2)
		conn, ok := ud.Value.(net.Conn)
		if !ok {
			L.Push(lua.LFalse)
			return 1
		}
		_, err := conn.Write([]byte(data))
		if err != nil {
			L.Push(lua.LFalse)
			return 1
		}
		L.Push(lua.LTrue)
		return 1
	}))

	// receive(conn, size, timeout_ms) → string
	L.SetGlobal("receive", L.NewFunction(func(L *lua.LState) int {
		ud := L.CheckUserData(1)
		size := L.OptInt(2, 4096)
		timeout := L.OptInt(3, 2000)
		conn, ok := ud.Value.(net.Conn)
		if !ok {
			L.Push(lua.LNil)
			return 1
		}
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
		buf := make([]byte, size)
		n, err := conn.Read(buf)
		if err != nil {
			L.Push(lua.LNil)
			return 1
		}
		L.Push(lua.LString(string(buf[:n])))
		return 1
	}))

	// close(conn)
	L.SetGlobal("close", L.NewFunction(func(L *lua.LState) int {
		ud := L.CheckUserData(1)
		if conn, ok := ud.Value.(net.Conn); ok {
			conn.Close()
		}
		return 0
	}))

	// sleep(ms)
	L.SetGlobal("sleep", L.NewFunction(func(L *lua.LState) int {
		ms := L.CheckInt(1)
		time.Sleep(time.Duration(ms) * time.Millisecond)
		return 0
	}))

	// log(msg) — debug logging
	L.SetGlobal("log", L.NewFunction(func(L *lua.LState) int {
		msg := L.CheckString(1)
		fmt.Fprintf(os.Stderr, "[LUA] %s\n", msg)
		return 0
	}))

	// grab_banner(host, port, timeout_ms) → string
	L.SetGlobal("grab_banner", L.NewFunction(func(L *lua.LState) int {
		h := L.CheckString(1)
		p := L.CheckInt(2)
		timeout := L.OptInt(3, 2000)
		banner := GrabBannerByHost(h, p, timeout)
		L.Push(lua.LString(banner))
		return 1
	}))
}
