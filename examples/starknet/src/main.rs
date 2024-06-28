use cairo_proof_parser::{parse, to_felts};
use clap::Parser;
use itertools::chain;
use runner::{CairoVersion, VecFelt252};
use starknet_ff::FieldElement;
use std::io::{stdin, Read};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Cairo version - public memory pattern
    #[clap(value_enum, short, long, default_value_t=CairoVersion::Cairo0)]
    cairo_version: CairoVersion,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut input = String::new();
    stdin().read_to_string(&mut input)?;

    let parsed = parse(&input)?;

    let proof: Vec<FieldElement> = to_felts(&parsed)?;
    let proof: VecFelt252 = proof.into();
    let calldata = chain!(proof, vec![cli.cairo_version.into()].into_iter());

    let calldata_string = calldata
        .map(|f| f.to_string())
        .collect::<Vec<String>>()
        .join(" ");

    println!("{}", calldata_string);

    Ok(())
}
