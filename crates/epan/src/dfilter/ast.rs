//! AST for the display-filter DSL.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub enum Expr {
    Field(String),                  // tcp.flags.syn
    FieldLayer(String, u32),        // tcp.port#udp  -or-  ip.src#2
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Mac([u8; 6]),
    XRef(String),
    MacroRef(String),
    Set(Vec<Expr>),                 // {80, 443}
    Range(Box<Expr>, Box<Expr>),    // 8080..8088
    Slice(Box<Expr>, Option<Box<Expr>>, Option<Box<Expr>>), // expr[a:b]
    RawBytes(String, Option<usize>, Option<usize>),         // @tcp[0:4]
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Unary(UnaryOp, Box<Expr>),
    Call(String, Vec<Expr>),         // upper(...), len(...), is_multicast(...)
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    And,
    Or,
    Contains,
    Matches,
    In,
    InSubnet,
    AnyEq,
    AllEq,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Tilde2, // any-byte-match
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
    BitNot,
}

/// Runtime value produced during evaluation.
#[derive(Debug, Clone)]
pub enum Value {
    None,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Mac([u8; 6]),
    Multi(Vec<Value>),
}

impl Value {
    pub fn truthy(&self) -> bool {
        match self {
            Value::None => false,
            Value::Bool(b) => *b,
            Value::Int(v) => *v != 0,
            Value::UInt(v) => *v != 0,
            Value::Float(v) => *v != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Bytes(b) => !b.is_empty(),
            Value::Ipv4(_) | Value::Ipv6(_) | Value::Mac(_) => true,
            Value::Multi(v) => v.iter().any(Value::truthy),
        }
    }
}
