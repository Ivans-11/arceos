# ksym

## Usage
```
nm -n -C {your kernel file} | grep ' [Tt] ' | grep -v '\.L' | grep -v '$x' | cargo run --bin gen_ksym --features="demangle"
```

## Output
It is like /proc/kallsyms:

``` 
ffffffc080200000 T _start
ffffffc080378070 T core::slice::index::slice_start_index_len_fail
ffffffc080379d12 T core::slice::index::slice_start_index_len_fail::do_panic::runtime
```