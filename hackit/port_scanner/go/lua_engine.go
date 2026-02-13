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

// LuaEngine handles NSE-style scripts
type LuaEngine struct {
	ScriptsDir string
}

func NewLuaEngine() *LuaEngine {
	// Default scripts directory relative to the binary
	dir, _ := os.Getwd()
	scriptsDir := filepath.Join(dir, "scripts")

	// Ensure directory exists
	if _, err := os.Stat(scriptsDir); os.IsNotExist(err) {
		os.MkdirAll(scriptsDir, 0755)
	}

	return &LuaEngine{
		ScriptsDir: scriptsDir,
	}
}

// RunScripts executes all applicable Lua scripts for a port
func (e *LuaEngine) RunScripts(host string, port int, service string, banner string) []string {
	var results []string

	files, err := os.ReadDir(e.ScriptsDir)
	if err != nil {
		return results
	}

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

	return results
}

func (e *LuaEngine) executeScript(path string, host string, port int, service string, banner string) (string, error) {
	// Create sandboxed state
	L := lua.NewState(lua.Options{
		SkipOpenLibs: true,
	})
	defer L.Close()

	// Open only safe libraries
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
		if err := L.CallByParam(lua.P{
			Fn:      L.NewFunction(lib.Fn),
			NRet:    0,
			Protect: true,
		}, lua.LString(lib.Name)); err != nil {
			panic(err)
		}
	}

	// Set execution timeout (Sandboxing)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	L.SetContext(ctx)

	// Register Go functions to Lua
	e.registerFunctions(L, host, port)

	// Inject context variables
	L.SetGlobal("host", lua.LString(host))
	L.SetGlobal("port", lua.LNumber(port))
	L.SetGlobal("service", lua.LString(service))
	L.SetGlobal("banner", lua.LString(banner))

	// Execute the script
	if err := L.DoFile(path); err != nil {
		return "", err
	}

	// Look for 'action' function or just global return
	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal("action"),
		NRet:    1,
		Protect: true,
	}); err != nil {
		// If action() doesn't exist, maybe it just ran global code
		return "", nil
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() == lua.LTString {
		return ret.String(), nil
	}

	return "", nil
}

func (e *LuaEngine) registerFunctions(L *lua.LState, host string, port int) {
	// socket.connect(host, port, timeout_ms)
	L.SetGlobal("connect", L.NewFunction(func(L *lua.LState) int {
		h := L.CheckString(1)
		p := L.CheckInt(2)
		timeout := L.OptInt(3, 2000)

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, p), time.Duration(timeout)*time.Millisecond)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}

		// Store conn in a Lua userdata or simple way (for this example, we'll use a simple wrapper)
		ud := L.NewUserData()
		ud.Value = conn
		L.Push(ud)
		return 1
	}))

	// socket.send(conn, data)
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

	// socket.receive(conn, size, timeout_ms)
	L.SetGlobal("receive", L.NewFunction(func(L *lua.LState) int {
		ud := L.CheckUserData(1)
		size := L.OptInt(2, 1024)
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

	// socket.close(conn)
	L.SetGlobal("close", L.NewFunction(func(L *lua.LState) int {
		ud := L.CheckUserData(1)
		conn, ok := ud.Value.(net.Conn)
		if ok {
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
}
