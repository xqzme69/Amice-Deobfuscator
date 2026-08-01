use anyhow::{Context, Result};
use pdb::{FallibleIterator, PDB, SymbolData};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Default)]
pub(crate) struct PeSymbolMap {
    exact: HashMap<u64, String>,
    ranges: Vec<(u64, u64, String)>,
}

impl PeSymbolMap {
    pub(crate) fn name_at(&self, address: u64) -> Option<String> {
        if let Some(name) = self.exact.get(&address) {
            return Some(name.clone());
        }
        if let Some((start, _, name)) = self
            .ranges
            .iter()
            .filter(|(start, end, _)| address >= *start && address < *end)
            .max_by_key(|(start, _, _)| *start)
        {
            return Some(format!("{name}+0x{:x}", address - start));
        }
        self.exact
            .iter()
            .filter(|(start, _)| address > **start && address - **start <= 0x1_0000)
            .max_by_key(|(start, _)| *start)
            .map(|(start, name)| format!("{name}+0x{:x}", address - start))
    }
}

pub(crate) fn load_pdb_symbols(path: &Path, image_base: u64) -> Result<PeSymbolMap> {
    let file = File::open(path).with_context(|| format!("open PDB {}", path.display()))?;
    let mut pdb = PDB::open(file).with_context(|| format!("parse PDB {}", path.display()))?;
    let address_map = pdb.address_map().context("read PDB address map")?;
    let mut result = PeSymbolMap::default();

    let globals = pdb.global_symbols().context("read PDB global symbols")?;
    let mut symbols = globals.iter();
    while let Some(symbol) = symbols.next().context("iterate PDB global symbols")? {
        if let Ok(SymbolData::Public(public)) = symbol.parse()
            && public.function
            && let Some(rva) = public.offset.to_rva(&address_map)
        {
            result
                .exact
                .entry(image_base + u64::from(rva.0))
                .or_insert_with(|| public.name.to_string().into_owned());
        }
    }

    let debug = pdb
        .debug_information()
        .context("read PDB debug information")?;
    let mut modules = debug.modules().context("read PDB modules")?;
    while let Some(module) = modules.next().context("iterate PDB modules")? {
        let Some(info) = pdb
            .module_info(&module)
            .context("read PDB module symbols")?
        else {
            continue;
        };
        let mut symbols = info.symbols().context("open PDB module symbol stream")?;
        let mut procedures = HashMap::new();
        let mut separated = Vec::new();
        while let Some(symbol) = symbols.next().context("iterate PDB module symbols")? {
            match symbol.parse() {
                Ok(SymbolData::Procedure(procedure)) => {
                    let name = procedure.name.to_string().into_owned();
                    procedures.insert(symbol.index().0, name.clone());
                    if let Some(rva) = procedure.offset.to_rva(&address_map) {
                        let start = image_base + u64::from(rva.0);
                        result.exact.insert(start, name.clone());
                        result
                            .ranges
                            .push((start, start + u64::from(procedure.len), name));
                    }
                }
                Ok(SymbolData::SeparatedCode(code)) => separated.push(code),
                _ => {}
            }
        }
        for code in separated {
            let Some(name) = procedures.get(&code.parent.0) else {
                continue;
            };
            if let Some(rva) = code.offset.to_rva(&address_map) {
                let start = image_base + u64::from(rva.0);
                result.exact.insert(start, name.clone());
                result
                    .ranges
                    .push((start, start + u64::from(code.len), name.clone()));
            }
        }
    }
    Ok(result)
}
