from .lua.lua_engine import LuaEngine
from .ruby.ruby_engine import RubyEngine

class PluginEngine:
    def __init__(self):
        self.lua = LuaEngine()
        self.ruby = RubyEngine()

    def available(self) -> list[str]:
        engines = []
        if self.lua.available():
            engines.append("lua")
        if self.ruby.available():
            engines.append("ruby")
        return engines

    def run_script(self, engine: str, script: str, args: list[str] = None) -> str:
        if engine == "lua":
            return self.lua.run(script, args)
        elif engine == "ruby":
            return self.ruby.run(script, args)
        raise ValueError(f"Unknown engine: {engine}")

    def list_scripts(self, engine: str) -> list[str]:
        if engine == "lua":
            return self.lua.list_scripts()
        elif engine == "ruby":
            return self.ruby.list_scripts()
        return []

__all__ = ["PluginEngine", "LuaEngine", "RubyEngine"]
