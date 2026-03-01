//! Display-filter evaluator over a built [`crate::ProtoTree`].

use super::ast::*;
use crate::proto::{FieldValue, ProtoTree};
use crate::register::Registry;
use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};

pub fn eval(expr: &Expr, tree: &ProtoTree, reg: &Registry) -> Result<Value, String> {
    match expr {
        Expr::UInt(v) => Ok(Value::UInt(*v)),
        Expr::Int(v) => Ok(Value::Int(*v)),
        Expr::Float(v) => Ok(Value::Float(*v)),
        Expr::Str(s) => Ok(Value::Str(s.clone())),
        Expr::Bytes(b) => Ok(Value::Bytes(b.clone())),
        Expr::Ipv4(a) => Ok(Value::Ipv4(*a)),
        Expr::Ipv6(a) => Ok(Value::Ipv6(*a)),
        Expr::Mac(m) => Ok(Value::Mac(*m)),
        Expr::Field(name) => Ok(lookup_field(name, tree, reg, None)),
        Expr::FieldLayer(name, idx) => Ok(lookup_field(name, tree, reg, Some(*idx as usize))),
        Expr::XRef(_) | Expr::MacroRef(_) => Ok(Value::None),
        Expr::Set(items) => {
            let vs = items.iter().map(|e| eval(e, tree, reg).unwrap_or(Value::None)).collect();
            Ok(Value::Multi(vs))
        }
        Expr::Range(a, b) => {
            let lo = to_u64(&eval(a, tree, reg)?).unwrap_or(0);
            let hi = to_u64(&eval(b, tree, reg)?).unwrap_or(0);
            let mut v = Vec::with_capacity((hi.saturating_sub(lo) + 1) as usize);
            for i in lo..=hi {
                v.push(Value::UInt(i));
            }
            Ok(Value::Multi(v))
        }
        Expr::Slice(inner, lo, hi) => {
            let v = eval(inner, tree, reg)?;
            let lo = lo.as_ref().map(|e| to_u64(&eval(e, tree, reg).unwrap_or(Value::None)).unwrap_or(0) as usize).unwrap_or(0);
            let hi = hi.as_ref().map(|e| to_u64(&eval(e, tree, reg).unwrap_or(Value::None)).unwrap_or(0) as usize);
            Ok(slice_value(&v, lo, hi))
        }
        Expr::RawBytes(name, lo, hi) => {
            let raw = first_proto_bytes(name, tree).unwrap_or_default();
            let lo = lo.unwrap_or(0).min(raw.len());
            let hi = hi.map(|h| h.min(raw.len())).unwrap_or(raw.len());
            Ok(Value::Bytes(raw[lo..hi].to_vec()))
        }
        Expr::Binary(op, l, r) => eval_binary(*op, l, r, tree, reg),
        Expr::Unary(op, e) => {
            let v = eval(e, tree, reg)?;
            Ok(match op {
                UnaryOp::Not => Value::Bool(!v.truthy()),
                UnaryOp::Neg => match v {
                    Value::Int(i) => Value::Int(-i),
                    Value::UInt(u) => Value::Int(-(u as i64)),
                    Value::Float(f) => Value::Float(-f),
                    _ => Value::None,
                },
                UnaryOp::BitNot => match v {
                    Value::Int(i) => Value::Int(!i),
                    Value::UInt(u) => Value::UInt(!u),
                    _ => Value::None,
                },
            })
        }
        Expr::Call(name, args) => eval_call(name, args, tree, reg),
        Expr::Ternary(c, t, e) => {
            if eval(c, tree, reg)?.truthy() {
                eval(t, tree, reg)
            } else {
                eval(e, tree, reg)
            }
        }
    }
}

fn eval_binary(op: BinOp, l: &Expr, r: &Expr, tree: &ProtoTree, reg: &Registry) -> Result<Value, String> {
    let lv = eval(l, tree, reg)?;
    let rv = eval(r, tree, reg)?;
    Ok(match op {
        BinOp::And => Value::Bool(lv.truthy() && rv.truthy()),
        BinOp::Or => Value::Bool(lv.truthy() || rv.truthy()),
        BinOp::Eq | BinOp::Ne | BinOp::Gt | BinOp::Lt | BinOp::Ge | BinOp::Le => {
            cmp_multi(&lv, &rv, op)
        }
        BinOp::Contains => Value::Bool(contains_op(&lv, &rv)),
        BinOp::Matches => match (&lv, &rv) {
            (l, Value::Str(rs)) => {
                if let Ok(re) = Regex::new(rs) {
                    Value::Bool(stringify_value(l).iter().any(|s| re.is_match(s)))
                } else {
                    Value::Bool(false)
                }
            }
            _ => Value::Bool(false),
        },
        BinOp::In => Value::Bool(in_op(&lv, &rv)),
        BinOp::InSubnet => Value::Bool(in_subnet_op(&lv, &rv)),
        BinOp::AnyEq => Value::Bool(any_eq(&lv, &rv)),
        BinOp::AllEq => Value::Bool(all_eq(&lv, &rv)),
        BinOp::BitAnd => bit_op(&lv, &rv, |a, b| a & b),
        BinOp::BitOr => bit_op(&lv, &rv, |a, b| a | b),
        BinOp::BitXor => bit_op(&lv, &rv, |a, b| a ^ b),
        BinOp::Shl => bit_op(&lv, &rv, |a, b| a << (b & 63)),
        BinOp::Shr => bit_op(&lv, &rv, |a, b| a >> (b & 63)),
        BinOp::Add => arith(&lv, &rv, |a, b| a + b, |a, b| a + b),
        BinOp::Sub => arith(&lv, &rv, |a, b| a - b, |a, b| a - b),
        BinOp::Mul => arith(&lv, &rv, |a, b| a * b, |a, b| a * b),
        BinOp::Div => arith(&lv, &rv, |a, b| if b == 0 { 0 } else { a / b }, |a, b| a / b),
        BinOp::Mod => arith(&lv, &rv, |a, b| if b == 0 { 0 } else { a % b }, |a, b| a % b),
        BinOp::Tilde2 => Value::Bool(any_byte_match(&lv, &rv)),
    })
}

fn cmp_multi(l: &Value, r: &Value, op: BinOp) -> Value {
    let lv = match l {
        Value::Multi(v) => v.clone(),
        other => vec![other.clone()],
    };
    let rv = match r {
        Value::Multi(v) => v.clone(),
        other => vec![other.clone()],
    };
    let any = lv.iter().any(|li| rv.iter().any(|ri| cmp_pair(li, ri, op)));
    Value::Bool(any)
}

fn cmp_pair(l: &Value, r: &Value, op: BinOp) -> bool {
    match op {
        BinOp::Eq => values_equal(l, r),
        BinOp::Ne => !values_equal(l, r),
        BinOp::Gt | BinOp::Ge | BinOp::Lt | BinOp::Le => match (l, r) {
            (Value::UInt(a), Value::UInt(b)) => match op {
                BinOp::Gt => a > b,
                BinOp::Ge => a >= b,
                BinOp::Lt => a < b,
                BinOp::Le => a <= b,
                _ => false,
            },
            (Value::Int(a), Value::Int(b)) => match op {
                BinOp::Gt => a > b,
                BinOp::Ge => a >= b,
                BinOp::Lt => a < b,
                BinOp::Le => a <= b,
                _ => false,
            },
            (Value::Float(a), Value::Float(b)) => match op {
                BinOp::Gt => a > b,
                BinOp::Ge => a >= b,
                BinOp::Lt => a < b,
                BinOp::Le => a <= b,
                _ => false,
            },
            _ => {
                let la = to_u64(l).unwrap_or(0);
                let rb = to_u64(r).unwrap_or(0);
                match op {
                    BinOp::Gt => la > rb,
                    BinOp::Ge => la >= rb,
                    BinOp::Lt => la < rb,
                    BinOp::Le => la <= rb,
                    _ => false,
                }
            }
        },
        _ => false,
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::UInt(x), Value::UInt(y)) => x == y,
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::UInt(x), Value::Int(y)) => *y >= 0 && *x == *y as u64,
        (Value::Int(x), Value::UInt(y)) => *x >= 0 && *x as u64 == *y,
        (Value::Float(x), Value::Float(y)) => x == y,
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::Bytes(x), Value::Bytes(y)) => x == y,
        (Value::Ipv4(x), Value::Ipv4(y)) => x == y,
        (Value::Ipv6(x), Value::Ipv6(y)) => x == y,
        (Value::Mac(x), Value::Mac(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        _ => false,
    }
}

fn contains_op(haystack: &Value, needle: &Value) -> bool {
    match (haystack, needle) {
        (Value::Str(h), Value::Str(n)) => h.contains(n.as_str()),
        (Value::Str(h), Value::Bytes(n)) => h.as_bytes().windows(n.len()).any(|w| w == n.as_slice()),
        (Value::Bytes(h), Value::Bytes(n)) => h.windows(n.len()).any(|w| w == n.as_slice()),
        (Value::Bytes(h), Value::Str(n)) => h.windows(n.len()).any(|w| w == n.as_bytes()),
        (Value::Multi(items), needle) => items.iter().any(|i| contains_op(i, needle)),
        _ => false,
    }
}

fn in_op(needle: &Value, set: &Value) -> bool {
    match set {
        Value::Multi(items) => items.iter().any(|i| values_equal(needle, i)),
        _ => values_equal(needle, set),
    }
}

fn in_subnet_op(addr: &Value, net: &Value) -> bool {
    if let Value::Str(s) = net {
        if let Some((ip, prefix)) = s.split_once('/') {
            let prefix: u8 = prefix.parse().unwrap_or(0);
            if let Ok(net_v4) = ip.parse::<Ipv4Addr>() {
                if let Value::Ipv4(a) = addr {
                    return wsutil::ip::in_subnet_v4(*a, net_v4, prefix);
                }
            }
            if let Ok(net_v6) = ip.parse::<Ipv6Addr>() {
                if let Value::Ipv6(a) = addr {
                    return wsutil::ip::in_subnet_v6(*a, net_v6, prefix);
                }
            }
        }
    }
    false
}

fn any_eq(l: &Value, r: &Value) -> bool {
    let items = match l {
        Value::Multi(v) => v.clone(),
        other => vec![other.clone()],
    };
    items.iter().any(|i| values_equal(i, r))
}

fn all_eq(l: &Value, r: &Value) -> bool {
    let items = match l {
        Value::Multi(v) => v.clone(),
        other => vec![other.clone()],
    };
    !items.is_empty() && items.iter().all(|i| values_equal(i, r))
}

fn bit_op(l: &Value, r: &Value, f: impl Fn(u64, u64) -> u64) -> Value {
    match (to_u64(l), to_u64(r)) {
        (Some(a), Some(b)) => Value::UInt(f(a, b)),
        _ => Value::None,
    }
}

fn arith(l: &Value, r: &Value, f_i: impl Fn(i64, i64) -> i64, f_f: impl Fn(f64, f64) -> f64) -> Value {
    if let (Some(a), Some(b)) = (to_i64(l), to_i64(r)) {
        return Value::Int(f_i(a, b));
    }
    if let (Some(a), Some(b)) = (to_f64(l), to_f64(r)) {
        return Value::Float(f_f(a, b));
    }
    Value::None
}

fn any_byte_match(l: &Value, r: &Value) -> bool {
    match (l, r) {
        (Value::Bytes(a), Value::Bytes(b)) => a.iter().any(|x| b.contains(x)),
        _ => false,
    }
}

fn slice_value(v: &Value, lo: usize, hi: Option<usize>) -> Value {
    match v {
        Value::Bytes(b) => {
            let end = hi.unwrap_or(b.len()).min(b.len());
            let start = lo.min(b.len()).min(end);
            Value::Bytes(b[start..end].to_vec())
        }
        Value::Str(s) => {
            let bytes = s.as_bytes();
            let end = hi.unwrap_or(bytes.len()).min(bytes.len());
            let start = lo.min(bytes.len()).min(end);
            Value::Str(String::from_utf8_lossy(&bytes[start..end]).into_owned())
        }
        _ => Value::None,
    }
}

fn first_proto_bytes(_proto: &str, _tree: &ProtoTree) -> Option<Vec<u8>> {
    None
}

fn stringify_value(v: &Value) -> Vec<String> {
    match v {
        Value::Str(s) => vec![s.clone()],
        Value::UInt(u) => vec![u.to_string()],
        Value::Int(i) => vec![i.to_string()],
        Value::Ipv4(a) => vec![a.to_string()],
        Value::Ipv6(a) => vec![a.to_string()],
        Value::Mac(m) => vec![wsutil::mac::format_mac(*m)],
        Value::Bytes(b) => vec![hex::encode(b)],
        Value::Multi(items) => items.iter().flat_map(stringify_value).collect(),
        _ => vec![],
    }
}

fn lookup_field(name: &str, tree: &ProtoTree, reg: &Registry, layer: Option<usize>) -> Value {
    let items = tree.find_all(reg, name);
    if items.is_empty() {
        return Value::None;
    }
    let chosen: Vec<&crate::proto::ProtoItem> = match layer {
        Some(idx) if idx > 0 && idx <= items.len() => vec![items[idx - 1]],
        _ => items,
    };
    let values: Vec<Value> = chosen.iter().filter_map(|it| field_value_to_value(&it.value)).collect();
    if values.len() == 1 {
        values.into_iter().next().unwrap()
    } else {
        Value::Multi(values)
    }
}

fn field_value_to_value(fv: &FieldValue) -> Option<Value> {
    Some(match fv {
        FieldValue::Bool(b) => Value::Bool(*b),
        FieldValue::U64(v) => Value::UInt(*v),
        FieldValue::I64(v) => Value::Int(*v),
        FieldValue::F64(v) => Value::Float(*v),
        FieldValue::Str(s) => Value::Str(s.clone()),
        FieldValue::Bytes(b) => Value::Bytes(b.clone()),
        FieldValue::Ipv4(a) => Value::Ipv4(*a),
        FieldValue::Ipv6(a) => Value::Ipv6(*a),
        FieldValue::Ether(m) => Value::Mac(*m),
        FieldValue::Frame(f) => Value::UInt(*f as u64),
        _ => return None,
    })
}

fn to_u64(v: &Value) -> Option<u64> {
    Some(match v {
        Value::UInt(u) => *u,
        Value::Int(i) if *i >= 0 => *i as u64,
        Value::Bool(b) => *b as u64,
        _ => return None,
    })
}

fn to_i64(v: &Value) -> Option<i64> {
    Some(match v {
        Value::Int(i) => *i,
        Value::UInt(u) if *u <= i64::MAX as u64 => *u as i64,
        Value::Bool(b) => *b as i64,
        _ => return None,
    })
}

fn to_f64(v: &Value) -> Option<f64> {
    Some(match v {
        Value::Float(f) => *f,
        Value::Int(i) => *i as f64,
        Value::UInt(u) => *u as f64,
        _ => return None,
    })
}

fn eval_call(name: &str, args: &[Expr], tree: &ProtoTree, reg: &Registry) -> Result<Value, String> {
    let evaluated: Vec<Value> = args.iter().map(|a| eval(a, tree, reg).unwrap_or(Value::None)).collect();
    Ok(match name {
        "len" | "length" => match evaluated.first() {
            Some(Value::Bytes(b)) => Value::UInt(b.len() as u64),
            Some(Value::Str(s)) => Value::UInt(s.len() as u64),
            Some(Value::Multi(v)) => Value::UInt(v.len() as u64),
            _ => Value::UInt(0),
        },
        "count" => match evaluated.first() {
            Some(Value::Multi(v)) => Value::UInt(v.len() as u64),
            Some(Value::None) => Value::UInt(0),
            _ => Value::UInt(1),
        },
        "upper" => match evaluated.into_iter().next() {
            Some(Value::Str(s)) => Value::Str(s.to_uppercase()),
            _ => Value::None,
        },
        "lower" => match evaluated.into_iter().next() {
            Some(Value::Str(s)) => Value::Str(s.to_lowercase()),
            _ => Value::None,
        },
        "string" => Value::Str(match evaluated.into_iter().next().unwrap_or(Value::None) {
            Value::UInt(v) => v.to_string(),
            Value::Int(v) => v.to_string(),
            Value::Str(s) => s,
            Value::Ipv4(a) => a.to_string(),
            Value::Ipv6(a) => a.to_string(),
            Value::Mac(m) => wsutil::mac::format_mac(m),
            Value::Bytes(b) => hex::encode(b),
            _ => String::new(),
        }),
        "min" | "max" => {
            let nums: Vec<i64> = evaluated.iter().filter_map(to_i64).collect();
            if nums.is_empty() {
                Value::None
            } else if name == "min" {
                Value::Int(*nums.iter().min().unwrap())
            } else {
                Value::Int(*nums.iter().max().unwrap())
            }
        }
        "is_multicast" => match evaluated.into_iter().next() {
            Some(Value::Ipv4(a)) => Value::Bool(wsutil::ip::is_multicast_v4(a)),
            Some(Value::Ipv6(a)) => Value::Bool(wsutil::ip::is_multicast_v6(a)),
            Some(Value::Mac(m)) => Value::Bool(wsutil::mac::is_multicast(m)),
            _ => Value::Bool(false),
        },
        "is_loopback" => match evaluated.into_iter().next() {
            Some(Value::Ipv4(a)) => Value::Bool(wsutil::ip::is_loopback_v4(a)),
            Some(Value::Ipv6(a)) => Value::Bool(wsutil::ip::is_loopback_v6(a)),
            _ => Value::Bool(false),
        },
        "is_link_local" => match evaluated.into_iter().next() {
            Some(Value::Ipv4(a)) => Value::Bool(wsutil::ip::is_link_local_v4(a)),
            Some(Value::Ipv6(a)) => Value::Bool(wsutil::ip::is_link_local_v6(a)),
            _ => Value::Bool(false),
        },
        "is_unicast" => match evaluated.into_iter().next() {
            Some(Value::Ipv4(a)) => Value::Bool(wsutil::ip::is_unicast_v4(a)),
            Some(Value::Ipv6(a)) => Value::Bool(wsutil::ip::is_unicast_v6(a)),
            _ => Value::Bool(false),
        },
        "slice" => match (evaluated.first(), evaluated.get(1), evaluated.get(2)) {
            (Some(v), Some(lo), hi) => {
                let lo = to_u64(lo).unwrap_or(0) as usize;
                let hi = hi.and_then(to_u64).map(|v| v as usize);
                slice_value(v, lo, hi)
            }
            _ => Value::None,
        },
        "hex" => Value::Str(match evaluated.into_iter().next() {
            Some(Value::Bytes(b)) => hex::encode(b),
            Some(Value::UInt(u)) => format!("0x{u:x}"),
            Some(Value::Int(i)) => format!("0x{i:x}"),
            _ => String::new(),
        }),
        "dec_to_int" | "int" => Value::Int(match evaluated.into_iter().next() {
            Some(Value::Str(s)) => s.parse().unwrap_or(0),
            Some(Value::UInt(u)) => u as i64,
            Some(Value::Int(i)) => i,
            _ => 0,
        }),
        _ => Value::None,
    })
}
