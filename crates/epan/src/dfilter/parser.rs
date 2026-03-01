//! Recursive-descent parser for the display-filter DSL.
//! Grammar (informally):
//!   expr      = or
//!   or        = and ( ("||"|"or") and )*
//!   and       = not ( ("&&"|"and") not )*
//!   not       = ("!"|"not") not | rel
//!   rel       = bitwise ( relop bitwise )?
//!   relop     = "==" | "!=" | ">" | "<" | ">=" | "<=" |
//!               contains | matches | in | in_subnet | "~=" |
//!               any_of | all_of
//!   bitwise   = shift ( ("&"|"|"|"^"|"bitand") shift )*
//!   shift     = additive ( ("<<"|">>") additive )*
//!   additive  = multiplicative ( ("+"|"-") multiplicative )*
//!   multiplicative = unary ( ("*"|"/"|"%") unary )*
//!   unary     = ("-"|"~") unary | postfix
//!   postfix   = primary ( "[" slice "]" )*
//!   primary   = literal | field | "(" expr ")" | call |
//!               set-literal | range-literal | "if" expr "then" expr "else" expr |
//!               raw-bytes ("@" ident "[" ... "]")

use super::ast::*;
use super::lexer::Token;

pub fn parse(tokens: &[Token]) -> Result<Expr, String> {
    let mut p = Parser { tokens, pos: 0 };
    let e = p.parse_or()?;
    p.expect(&Token::Eof)?;
    Ok(e)
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }
    fn bump(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        self.pos += 1;
        t
    }
    fn check(&self, t: &Token) -> bool {
        std::mem::discriminant(self.peek()) == std::mem::discriminant(t)
    }
    fn eat(&mut self, t: &Token) -> bool {
        if self.check(t) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, t: &Token) -> Result<(), String> {
        if self.check(t) {
            self.bump();
            Ok(())
        } else {
            Err(format!("expected {t:?}, got {:?}", self.peek()))
        }
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Token::OrOr | Token::KwOr) {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Binary(BinOp::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Token::AndAnd | Token::KwAnd) {
            self.bump();
            let right = self.parse_not()?;
            left = Expr::Binary(BinOp::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Token::Bang | Token::KwNot) {
            self.bump();
            let inner = self.parse_not()?;
            return Ok(Expr::Unary(UnaryOp::Not, Box::new(inner)));
        }
        self.parse_rel()
    }

    fn parse_rel(&mut self) -> Result<Expr, String> {
        let left = self.parse_bitwise()?;
        let op = match self.peek() {
            Token::Eq => Some(BinOp::Eq),
            Token::Ne => Some(BinOp::Ne),
            Token::Gt => Some(BinOp::Gt),
            Token::Lt => Some(BinOp::Lt),
            Token::Ge => Some(BinOp::Ge),
            Token::Le => Some(BinOp::Le),
            Token::KwContains => Some(BinOp::Contains),
            Token::KwMatches => Some(BinOp::Matches),
            Token::KwIn => Some(BinOp::In),
            Token::KwInSubnet => Some(BinOp::InSubnet),
            Token::Tilde2 => Some(BinOp::Tilde2),
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let right = self.parse_bitwise()?;
            return Ok(Expr::Binary(op, Box::new(left), Box::new(right)));
        }
        Ok(left)
    }

    fn parse_bitwise(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_shift()?;
        loop {
            let op = match self.peek() {
                Token::Amp | Token::KwBitand => BinOp::BitAnd,
                Token::Pipe => BinOp::BitOr,
                Token::Caret => BinOp::BitXor,
                _ => break,
            };
            self.bump();
            let right = self.parse_shift()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_shift(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_addsub()?;
        loop {
            let op = match self.peek() {
                Token::Shl => BinOp::Shl,
                Token::Shr => BinOp::Shr,
                _ => break,
            };
            self.bump();
            let right = self.parse_addsub()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_addsub(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_muldiv()?;
        loop {
            let op = match self.peek() {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => break,
            };
            self.bump();
            let right = self.parse_muldiv()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_muldiv(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Star => BinOp::Mul,
                Token::Slash => BinOp::Div,
                Token::Percent => BinOp::Mod,
                _ => break,
            };
            self.bump();
            let right = self.parse_unary()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Token::Minus => {
                self.bump();
                Ok(Expr::Unary(UnaryOp::Neg, Box::new(self.parse_unary()?)))
            }
            Token::Tilde => {
                self.bump();
                Ok(Expr::Unary(UnaryOp::BitNot, Box::new(self.parse_unary()?)))
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_primary()?;
        loop {
            if self.eat(&Token::LBracket) {
                let lo = if matches!(self.peek(), Token::Colon | Token::RBracket) {
                    None
                } else {
                    Some(Box::new(self.parse_or()?))
                };
                let hi = if self.eat(&Token::Colon) {
                    if !self.check(&Token::RBracket) {
                        Some(Box::new(self.parse_or()?))
                    } else {
                        None
                    }
                } else {
                    None
                };
                self.expect(&Token::RBracket)?;
                e = Expr::Slice(Box::new(e), lo, hi);
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.peek().clone() {
            Token::UInt(v) => { self.bump(); Ok(Expr::UInt(v)) }
            Token::Int(v) => { self.bump(); Ok(Expr::Int(v)) }
            Token::Float(v) => { self.bump(); Ok(Expr::Float(v)) }
            Token::Str(s) => { self.bump(); Ok(Expr::Str(s)) }
            Token::Bytes(b) => { self.bump(); Ok(Expr::Bytes(b)) }
            Token::Ipv4(a) => { self.bump(); Ok(Expr::Ipv4(a)) }
            Token::Ipv6(a) => { self.bump(); Ok(Expr::Ipv6(a)) }
            Token::Mac(m) => { self.bump(); Ok(Expr::Mac(m)) }
            Token::XRef(name) => { self.bump(); Ok(Expr::XRef(name)) }
            Token::MacroRef(name) => { self.bump(); Ok(Expr::MacroRef(name)) }
            Token::LParen => {
                self.bump();
                let e = self.parse_or()?;
                self.expect(&Token::RParen)?;
                Ok(e)
            }
            Token::LBrace => {
                self.bump();
                let mut items = Vec::new();
                if !self.check(&Token::RBrace) {
                    loop {
                        let e = self.parse_or()?;
                        if self.eat(&Token::DotDot) {
                            let hi = self.parse_or()?;
                            items.push(Expr::Range(Box::new(e), Box::new(hi)));
                        } else {
                            items.push(e);
                        }
                        if !self.eat(&Token::Comma) {
                            break;
                        }
                    }
                }
                self.expect(&Token::RBrace)?;
                Ok(Expr::Set(items))
            }
            Token::At => {
                // @tcp[0:4]
                self.bump();
                let name = match self.bump() {
                    Token::Ident(s) => s,
                    other => return Err(format!("expected identifier after @, got {other:?}")),
                };
                let (lo, hi) = if self.eat(&Token::LBracket) {
                    let lo = if let Token::UInt(v) = self.peek().clone() {
                        self.bump();
                        Some(v as usize)
                    } else {
                        None
                    };
                    self.expect(&Token::Colon).ok();
                    let hi = if let Token::UInt(v) = self.peek().clone() {
                        self.bump();
                        Some(v as usize)
                    } else {
                        None
                    };
                    self.expect(&Token::RBracket)?;
                    (lo, hi)
                } else {
                    (None, None)
                };
                Ok(Expr::RawBytes(name, lo, hi))
            }
            Token::Ident(name) => {
                self.bump();
                // function call?
                if self.eat(&Token::LParen) {
                    let mut args = Vec::new();
                    if !self.check(&Token::RParen) {
                        loop {
                            args.push(self.parse_or()?);
                            if !self.eat(&Token::Comma) {
                                break;
                            }
                        }
                    }
                    self.expect(&Token::RParen)?;
                    return Ok(Expr::Call(name, args));
                }
                // layer index suffix: tcp.port#udp  -or-  ip.src#2
                if self.eat(&Token::Hash) {
                    let layer = self.bump();
                    let layer_str = match layer {
                        Token::Ident(s) => s,
                        Token::UInt(v) => v.to_string(),
                        other => return Err(format!("expected layer name/index after '#', got {other:?}")),
                    };
                    return Ok(Expr::FieldLayer(name, layer_str.parse().unwrap_or(0)));
                }
                Ok(Expr::Field(name))
            }
            Token::KwIf => {
                self.bump();
                let cond = self.parse_or()?;
                self.expect(&Token::KwThen)?;
                let then_e = self.parse_or()?;
                self.expect(&Token::KwElse)?;
                let else_e = self.parse_or()?;
                Ok(Expr::Ternary(Box::new(cond), Box::new(then_e), Box::new(else_e)))
            }
            Token::KwAnyOf | Token::KwAllOf => {
                let kw = self.bump();
                self.expect(&Token::LParen)?;
                let inner_field = match self.bump() {
                    Token::Ident(s) => s,
                    other => return Err(format!("any_of/all_of expects a field name, got {other:?}")),
                };
                self.expect(&Token::RParen)?;
                // The op + rhs follow: any_of(ip.addr) == 10.0.0.1
                let op = match self.peek() {
                    Token::Eq => BinOp::AnyEq,
                    _ => return Err("any_of/all_of must be followed by ==".into()),
                };
                self.bump();
                let rhs = self.parse_bitwise()?;
                let real_op = match kw {
                    Token::KwAnyOf => op,
                    Token::KwAllOf => BinOp::AllEq,
                    _ => unreachable!(),
                };
                Ok(Expr::Binary(real_op, Box::new(Expr::Field(inner_field)), Box::new(rhs)))
            }
            other => Err(format!("unexpected token in expression: {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::lexer::tokenize;
    use super::*;

    #[test]
    fn simple_eq() {
        let toks = tokenize("tcp.flags.syn == 1").unwrap();
        let e = parse(&toks).unwrap();
        match e {
            Expr::Binary(BinOp::Eq, _, _) => {}
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn set_literal() {
        let toks = tokenize("tcp.dstport in {80, 443, 8080}").unwrap();
        let _ = parse(&toks).unwrap();
    }

    #[test]
    fn nested_and_or() {
        let toks = tokenize(r#"http.host == "x" && (tcp.port == 80 || tcp.port == 443)"#).unwrap();
        let _ = parse(&toks).unwrap();
    }
}
