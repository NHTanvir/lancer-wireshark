//! Token stream for the display-filter DSL.

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),       // tcp.flags.syn
    MacroRef(String),    // @{macro_name}
    XRef(String),        // ${tcp.seq}  (cross-packet)
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Ipv4(std::net::Ipv4Addr),
    Ipv6(std::net::Ipv6Addr),
    Mac([u8; 6]),
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Dot,
    DotDot, // ..
    Colon,
    Hash, // #udp suffix or #2 layer slice
    At,   // @tcp[0:4]
    Bang,
    Tilde,
    Amp,
    Pipe,
    Caret,
    Shl,
    Shr,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eq,    // ==
    Ne,    // !=
    Gt,
    Lt,
    Ge,
    Le,
    AndAnd,
    OrOr,
    Tilde2, // ~= (any byte match)
    KwContains,
    KwMatches,
    KwIn,
    KwInSubnet,
    KwAnd,
    KwOr,
    KwNot,
    KwAnyOf,
    KwAllOf,
    KwIf,
    KwThen,
    KwElse,
    KwBitand,
    Eof,
}

pub fn tokenize(s: &str) -> Result<Vec<Token>, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // strings
        if c == b'"' {
            let (tok, n) = read_string(&bytes[i..])?;
            out.push(tok);
            i += n;
            continue;
        }
        // byte sequence like 11:22:33 or 11-22-33
        if c.is_ascii_hexdigit() && looks_like_bytes(&bytes[i..]) {
            let (tok, n) = read_bytes_seq(&bytes[i..]);
            out.push(tok);
            i += n;
            continue;
        }
        // numbers (decimal / hex / float)
        if c.is_ascii_digit() {
            let (tok, n) = read_number(&bytes[i..])?;
            out.push(tok);
            i += n;
            continue;
        }
        // identifiers / keywords
        if c.is_ascii_alphabetic() || c == b'_' {
            let (tok, n) = read_ident(&bytes[i..]);
            out.push(tok);
            i += n;
            continue;
        }
        // operators / punctuation
        let (tok, n) = match c {
            b'(' => (Token::LParen, 1),
            b')' => (Token::RParen, 1),
            b'[' => (Token::LBracket, 1),
            b']' => (Token::RBracket, 1),
            b'{' => (Token::LBrace, 1),
            b'}' => (Token::RBrace, 1),
            b',' => (Token::Comma, 1),
            b'.' if bytes.get(i + 1) == Some(&b'.') => (Token::DotDot, 2),
            b'.' => (Token::Dot, 1),
            b':' => (Token::Colon, 1),
            b'#' => (Token::Hash, 1),
            b'@' => {
                // could be @{macro_name} or @tcp[0:4]
                if bytes.get(i + 1) == Some(&b'{') {
                    let end = bytes[i + 2..].iter().position(|&c| c == b'}').ok_or("unterminated @{...}")?;
                    let name = std::str::from_utf8(&bytes[i + 2..i + 2 + end]).unwrap().to_string();
                    (Token::MacroRef(name), 3 + end)
                } else {
                    (Token::At, 1)
                }
            }
            b'!' if bytes.get(i + 1) == Some(&b'=') => (Token::Ne, 2),
            b'!' => (Token::Bang, 1),
            b'~' if bytes.get(i + 1) == Some(&b'=') => (Token::Tilde2, 2),
            b'~' => (Token::Tilde, 1),
            b'&' if bytes.get(i + 1) == Some(&b'&') => (Token::AndAnd, 2),
            b'&' => (Token::Amp, 1),
            b'|' if bytes.get(i + 1) == Some(&b'|') => (Token::OrOr, 2),
            b'|' => (Token::Pipe, 1),
            b'^' => (Token::Caret, 1),
            b'<' if bytes.get(i + 1) == Some(&b'<') => (Token::Shl, 2),
            b'<' if bytes.get(i + 1) == Some(&b'=') => (Token::Le, 2),
            b'<' => (Token::Lt, 1),
            b'>' if bytes.get(i + 1) == Some(&b'>') => (Token::Shr, 2),
            b'>' if bytes.get(i + 1) == Some(&b'=') => (Token::Ge, 2),
            b'>' => (Token::Gt, 1),
            b'=' if bytes.get(i + 1) == Some(&b'=') => (Token::Eq, 2),
            b'+' => (Token::Plus, 1),
            b'-' => (Token::Minus, 1),
            b'*' => (Token::Star, 1),
            b'/' => (Token::Slash, 1),
            b'%' => (Token::Percent, 1),
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                let end = bytes[i + 2..].iter().position(|&c| c == b'}').ok_or("unterminated ${...}")?;
                let name = std::str::from_utf8(&bytes[i + 2..i + 2 + end]).unwrap().to_string();
                (Token::XRef(name), 3 + end)
            }
            _ => return Err(format!("unexpected character at offset {i}: {:?}", c as char)),
        };
        out.push(tok);
        i += n;
    }
    out.push(Token::Eof);
    Ok(out)
}

fn read_string(buf: &[u8]) -> Result<(Token, usize), String> {
    let mut out = String::new();
    let mut i = 1;
    while i < buf.len() && buf[i] != b'"' {
        if buf[i] == b'\\' && i + 1 < buf.len() {
            match buf[i + 1] {
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'\\' => out.push('\\'),
                b'"' => out.push('"'),
                other => out.push(other as char),
            }
            i += 2;
        } else {
            out.push(buf[i] as char);
            i += 1;
        }
    }
    if i >= buf.len() {
        return Err("unterminated string".into());
    }
    Ok((Token::Str(out), i + 1))
}

fn read_number(buf: &[u8]) -> Result<(Token, usize), String> {
    // hex
    if buf.len() >= 2 && buf[0] == b'0' && (buf[1] == b'x' || buf[1] == b'X') {
        let mut j = 2;
        while j < buf.len() && buf[j].is_ascii_hexdigit() {
            j += 1;
        }
        let n =
            u64::from_str_radix(std::str::from_utf8(&buf[2..j]).unwrap(), 16).map_err(|e| e.to_string())?;
        return Ok((Token::UInt(n), j));
    }
    let mut j = 0;
    while j < buf.len() && buf[j].is_ascii_digit() {
        j += 1;
    }
    if j < buf.len() && buf[j] == b'.' && buf.get(j + 1).map(|c| c.is_ascii_digit()).unwrap_or(false) {
        let mut k = j + 1;
        while k < buf.len() && buf[k].is_ascii_digit() {
            k += 1;
        }
        let s = std::str::from_utf8(&buf[..k]).unwrap();
        let v: f64 = s.parse().map_err(|e: std::num::ParseFloatError| e.to_string())?;
        return Ok((Token::Float(v), k));
    }
    let s = std::str::from_utf8(&buf[..j]).unwrap();
    let v: u64 = s.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
    Ok((Token::UInt(v), j))
}

fn looks_like_bytes(buf: &[u8]) -> bool {
    // heuristic: hex pairs separated by ':' or '-'
    buf.len() >= 5
        && buf[0].is_ascii_hexdigit()
        && buf[1].is_ascii_hexdigit()
        && (buf[2] == b':' || buf[2] == b'-')
        && buf[3].is_ascii_hexdigit()
        && buf[4].is_ascii_hexdigit()
}

fn read_bytes_seq(buf: &[u8]) -> (Token, usize) {
    let mut i = 0;
    let mut bytes = Vec::new();
    while i + 1 < buf.len() && buf[i].is_ascii_hexdigit() && buf[i + 1].is_ascii_hexdigit() {
        let s = std::str::from_utf8(&buf[i..i + 2]).unwrap();
        bytes.push(u8::from_str_radix(s, 16).unwrap_or(0));
        i += 2;
        if i < buf.len() && (buf[i] == b':' || buf[i] == b'-') {
            i += 1;
        } else {
            break;
        }
    }
    if bytes.len() == 6 {
        let mac = [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]];
        (Token::Mac(mac), i)
    } else {
        (Token::Bytes(bytes), i)
    }
}

fn read_ident(buf: &[u8]) -> (Token, usize) {
    let mut j = 0;
    while j < buf.len() && (buf[j].is_ascii_alphanumeric() || buf[j] == b'_' || buf[j] == b'.') {
        j += 1;
    }
    let s = std::str::from_utf8(&buf[..j]).unwrap().to_string();
    let tok = match s.as_str() {
        "and" => Token::KwAnd,
        "or" => Token::KwOr,
        "not" => Token::KwNot,
        "contains" => Token::KwContains,
        "matches" => Token::KwMatches,
        "in" => Token::KwIn,
        "in_subnet" => Token::KwInSubnet,
        "any_of" => Token::KwAnyOf,
        "all_of" => Token::KwAllOf,
        "if" => Token::KwIf,
        "then" => Token::KwThen,
        "else" => Token::KwElse,
        "bitand" => Token::KwBitand,
        "eq" => Token::Eq,
        "ne" => Token::Ne,
        "gt" => Token::Gt,
        "lt" => Token::Lt,
        "ge" => Token::Ge,
        "le" => Token::Le,
        _ => {
            // try to parse as an IP address literal
            if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
                return (Token::Ipv4(v4), j);
            }
            if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
                return (Token::Ipv6(v6), j);
            }
            Token::Ident(s)
        }
    };
    (tok, j)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_eq() {
        let t = tokenize("ip.addr == 10.0.0.1").unwrap();
        assert!(matches!(t[0], Token::Ident(_)));
        assert!(matches!(t[1], Token::Eq));
        assert!(matches!(t[2], Token::Ipv4(_)));
    }

    #[test]
    fn parse_string() {
        let t = tokenize(r#"http.host == "example.com""#).unwrap();
        assert!(matches!(t[2], Token::Str(_)));
    }

    #[test]
    fn parse_hex() {
        let t = tokenize("0xCAFE").unwrap();
        assert_eq!(t[0], Token::UInt(0xCAFE));
    }
}
