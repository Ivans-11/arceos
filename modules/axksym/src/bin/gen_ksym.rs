use std::str;

use rustc_demangle::demangle;

#[derive(Debug, Clone)]
struct KernelSymbolEntry {
    vaddr: u64,
    symbol: String,
}

fn read_symbol(line: &str) -> Option<KernelSymbolEntry> {
    if line.len() > 512 {
        return None;
    } // skip line with length >= 512
    let mut parts = line.split_whitespace();
    let vaddr = u64::from_str_radix(parts.next()?, 16).ok()?;
    let symbol_type = parts.next()?.chars().next()?;
    let mut symbol = parts.collect::<Vec<_>>().join(" ");
    if symbol_type != 'T' && symbol_type != 't' {
        return None;
    } // local symbol or global symbol in text section
    if symbol.contains("$x") {
        return None;
    } // skip $x symbol
    if symbol.starts_with("_ZN") {
        symbol = format!("{:#}", demangle(&symbol));
    } else {
        symbol = format!("{}", symbol);
    }
    Some(KernelSymbolEntry { vaddr, symbol })
}

fn read_map(path: &str) -> Vec<KernelSymbolEntry> {
    let contents = std::fs::read_to_string(path).expect("Failed to read the map file");
    let mut symbol_table = Vec::new();
    for line in contents.lines() {
        if let Some(entry) = read_symbol(line) {
            symbol_table.push(entry);
        }
    }
    symbol_table
}

fn generate_result(symbol_table: &[KernelSymbolEntry]) {
    // Generate ksyms_address
    // like /proc/kallsyms
    eprintln!("Generating kernel symbols: {} entries", symbol_table.len());
    for entry in symbol_table {
        print!("{:016x} T {}\n", entry.vaddr, entry.symbol);
    }
}

fn main() {
    let args = std::env::args();
    let path = args.into_iter().nth(1);
    if let Some(p) = path {
        eprintln!("Reading symbols from: {}", p);
        let symbol_table = read_map(&p);
        generate_result(&symbol_table);
    } else {
        eprintln!("Please provide the path to the symbol file as an argument.");
    }
}
