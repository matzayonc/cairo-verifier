use cairo_verifier::{
    tests::{stone_proof_fibonacci, stone_proof_fibonacci_keccak},
    air::{public_input::PublicInputTrait}, domains::StarkDomainsTrait
};

// === BLAKE ONLY BEGIN ===
// #[test]
// #[available_gas(9999999999)]
// fn test_public_input_hash() {
//     let public_input = stone_proof_fibonacci::public_input::get();
// 
//     assert(public_input.get_public_input_hash() == 0x0, 'Invalid value')
// }
// 
// #[test]
// #[available_gas(9999999999)]
// fn test_public_input_validate() {
//     let public_input = stone_proof_fibonacci::public_input::get();
// 
//     let log_trace_domain_size = 0x12;
//     let log_n_cosets = 0x4;
//     let domain = StarkDomainsTrait::new(log_trace_domain_size, log_n_cosets);
// 
//     public_input.validate(@domain);
// }
// 
// #[test]
// #[available_gas(9999999999)]
// fn test_public_input_verify() {
//     let public_input = stone_proof_fibonacci::public_input::get();
//     let (program_hash, output_hash) = public_input.verify();
// 
//     assert(
//         program_hash == 0x9f6693f4a5610a46b5d71ef573c43bef5f0d111fc1c5e506d509c458a29bae,
//         'Wrong program hash'
//     );
//     assert(
//         output_hash == 0x3cff7dfd4138a3c9082a6a768b1c094ae290e2f4705482bf0eb2dbb21c46968,
//         'Wrong output hash'
//     );
// }
// === BLAKE ONLY END ===

// === KECCAK ONLY BEGIN ===
#[test]
#[available_gas(9999999999)]
fn test_public_input_hash() {
    let public_input = stone_proof_fibonacci_keccak::public_input::get();

    assert(public_input.get_public_input_hash() == 0x0, 'Invalid value')
}

#[test]
#[available_gas(9999999999)]
fn test_public_input_validate() {
    let public_input = stone_proof_fibonacci_keccak::public_input::get();

    let log_trace_domain_size = 0x12;
    let log_n_cosets = 0x4;
    let domain = StarkDomainsTrait::new(log_trace_domain_size, log_n_cosets);

    public_input.validate(@domain);
}
// === KECCAK ONLY END ===


