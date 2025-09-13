#![no_std]

use alloc::{format, string::String, vec::Vec};

use lazyinit::LazyInit;
extern crate alloc;

pub static KSYM: LazyInit<Vec<(String, usize)>> = LazyInit::new();

/// Initialize the kernel symbol table from a string in the format of
/// /proc/kallsyms
pub fn init_kernel_symbols(ksym: &str) {
    let mut symbol_table = Vec::new();
    for line in ksym.lines() {
        let mut parts = line.split_whitespace();
        let vaddr = usize::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let symbol_type = parts.next().and_then(|s| s.chars().next()).unwrap_or(' ');
        let symbol = parts.collect::<Vec<_>>().join(" ");
        if symbol_type == 'T' || symbol_type == 't' {
            symbol_table.push((symbol, vaddr));
        }
    }

    KSYM.init_once(symbol_table);
}

/// Return the function information according to the pc address and
pub fn lookup_kallsyms(addr: usize, level: i32) -> String {
    let mut index = usize::MAX;
    let ksym = KSYM.get().unwrap();
    let sym_num = ksym.len();
    for i in 0..sym_num - 1 {
        if addr > ksym[i].1 && addr <= ksym[i + 1].1 {
            index = i;
            break;
        }
    }
    if index < sym_num {
        let sym_name = ksym[index].0.as_str();
        format!(
            "[{}] function:{}() \t(+) {:04} address:{:#018x}",
            level,
            sym_name,
            addr - ksym[index].1,
            addr
        )
    } else {
        format!(
            "[{}] function:unknown \t(+) {:04} address:{:#018x}",
            level,
            addr - ksym[sym_num - 1].1,
            addr
        )
    }
}

/// Get the address of the symbol
pub fn addr_from_symbol(symbol: &str) -> Option<usize> {
    let ksym = KSYM.get().unwrap();
    for (name, addr) in ksym {
        if name == symbol {
            return Some(*addr);
        }
    }
    None
}
