//! Lua 5.4 scripting bridge — lets users write Wireshark-style Lua
//! dissectors and run them from the GUI / CLI.
//!
//! The mlua 0.10 series removed the `'lua` lifetime from most types, so
//! `Lua` values are no longer Send. This bridge runs scripts on the
//! caller's thread; integration with the engine happens by registering
//! returned dissector tables back through [`epan::Registry`].

use anyhow::Result;
use mlua::prelude::*;
use mlua::Function;

pub struct LuaEngine {
    pub lua: Lua,
}

impl LuaEngine {
    pub fn new() -> Result<Self> {
        let lua = Lua::new();
        register_globals(&lua).map_err(|e| anyhow::anyhow!("lua: {e}"))?;
        Ok(Self { lua })
    }

    pub fn load_file(&self, path: &str) -> Result<()> {
        let src = std::fs::read_to_string(path)?;
        self.lua
            .load(&src)
            .set_name(path)
            .exec()
            .map_err(|e| anyhow::anyhow!("lua exec {path}: {e}"))?;
        Ok(())
    }

    pub fn load_str(&self, src: &str, chunkname: &str) -> Result<()> {
        self.lua
            .load(src)
            .set_name(chunkname)
            .exec()
            .map_err(|e| anyhow::anyhow!("lua exec {chunkname}: {e}"))?;
        Ok(())
    }

    /// Call a global Lua function with no arguments.
    pub fn call(&self, name: &str) -> Result<()> {
        let f: Function = self
            .lua
            .globals()
            .get(name)
            .map_err(|e| anyhow::anyhow!("missing {name}: {e}"))?;
        f.call::<()>(()).map_err(|e| anyhow::anyhow!("call {name}: {e}"))?;
        Ok(())
    }
}

impl Default for LuaEngine {
    fn default() -> Self {
        Self::new().expect("lua init")
    }
}

fn register_globals(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();

    let proto_tbl = lua.create_table()?;
    proto_tbl.set(
        "new",
        lua.create_function(|_, (short, name): (String, String)| {
            Ok(LuaProto { short, name })
        })?,
    )?;
    globals.set("Proto", proto_tbl)?;

    let pf_tbl = lua.create_table()?;
    pf_tbl.set(
        "new",
        lua.create_function(|_, (abbr, name, ty): (String, String, String)| {
            Ok(LuaProtoField { abbr, name, ty })
        })?,
    )?;
    globals.set("ProtoField", pf_tbl)?;

    Ok(())
}

#[derive(Clone)]
pub struct LuaProto {
    pub short: String,
    pub name: String,
}

impl LuaUserData for LuaProto {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("short", |_, this, ()| Ok(this.short.clone()));
        methods.add_method("name", |_, this, ()| Ok(this.name.clone()));
    }
}

#[derive(Clone)]
pub struct LuaProtoField {
    pub abbr: String,
    pub name: String,
    pub ty: String,
}

impl LuaUserData for LuaProtoField {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("abbr", |_, this, ()| Ok(this.abbr.clone()));
        methods.add_method("ty", |_, this, ()| Ok(this.ty.clone()));
    }
}

#[derive(Clone)]
pub struct LuaTvb {
    pub bytes: Vec<u8>,
}

impl LuaUserData for LuaTvb {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("len", |_, this, ()| Ok(this.bytes.len()));
        methods.add_method("u8", |_, this, off: usize| Ok(this.bytes.get(off).copied()));
        methods.add_method("u16_be", |_, this, off: usize| {
            Ok(this
                .bytes
                .get(off..off + 2)
                .map(|s| u16::from_be_bytes([s[0], s[1]])))
        });
        methods.add_method("u32_be", |_, this, off: usize| {
            Ok(this
                .bytes
                .get(off..off + 4)
                .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]])))
        });
        methods.add_method("bytes", |_, this, (off, len): (usize, usize)| {
            Ok(this.bytes.get(off..off + len).map(|s| s.to_vec()))
        });
        methods.add_method("string", |_, this, (off, len): (usize, usize)| {
            Ok(this.bytes.get(off..off + len).and_then(|s| String::from_utf8(s.to_vec()).ok()))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_basic_script() {
        let e = LuaEngine::new().unwrap();
        e.load_str("function add(a, b) return a + b end; result = add(2, 3)", "test").unwrap();
        let v: i64 = e.lua.globals().get("result").unwrap();
        assert_eq!(v, 5);
    }
}
