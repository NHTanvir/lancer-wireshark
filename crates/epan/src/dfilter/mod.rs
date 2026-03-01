//! Display-filter DSL — parser, type-checker and evaluator.
//!
//! Wireshark uses flex+bison; we use a hand-rolled recursive descent parser
//! to keep the build dependency-free and easy to grow.
//!
//! Public surface:
//! - [`Dfilter::compile`] — parse + type-check a filter source string.
//! - [`Dfilter::matches`] — evaluate against a [`crate::ProtoTree`].

pub mod lexer;
pub mod parser;
pub mod ast;
pub mod eval;

pub use ast::{Expr, Value, BinOp, UnaryOp};

use crate::register::Registry;
use crate::proto::ProtoTree;

#[derive(Debug, thiserror::Error)]
pub enum DfilterError {
    #[error("lexer: {0}")]
    Lex(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("type: {0}")]
    Type(String),
    #[error("eval: {0}")]
    Eval(String),
}

pub struct Dfilter {
    pub source: String,
    pub expr: Expr,
}

impl Dfilter {
    pub fn compile(src: &str, _reg: &Registry) -> Result<Self, DfilterError> {
        let tokens = lexer::tokenize(src).map_err(DfilterError::Lex)?;
        let expr = parser::parse(&tokens).map_err(DfilterError::Parse)?;
        Ok(Dfilter {
            source: src.to_string(),
            expr,
        })
    }

    pub fn matches(&self, tree: &ProtoTree, reg: &Registry) -> bool {
        eval::eval(&self.expr, tree, reg).map(|v| v.truthy()).unwrap_or(false)
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}
