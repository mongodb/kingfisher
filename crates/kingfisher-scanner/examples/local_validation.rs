//! Optional validation is explicit; this example makes no network requests.
use kingfisher_rules::EthereumValidation;
use kingfisher_scanner::{ValidationOutcome, validation::ethereum};

fn main() {
    let result = ethereum::validate(EthereumValidation::PrivateKey, "invalid-example-input");
    assert_eq!(result.outcome, ValidationOutcome::InvalidMaterial);
    println!("Validation outcome: {:?}", result.outcome);
}
