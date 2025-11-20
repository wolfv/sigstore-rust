//! Example: Verify a Sigstore bundle
//!
//! This example demonstrates how to verify a Sigstore bundle against an artifact.
//!
//! Usage:
//!   cargo run --example verify_bundle -- <artifact> <bundle.sigstore.json>
//!   cargo run --example verify_bundle -- --demo

use sigstore::bundle::validate_bundle_with_options;
use sigstore::bundle::ValidationOptions;
use sigstore::types::Bundle;
use sigstore::verify::{verify, VerificationPolicy};
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 && args[1] == "--demo" {
        run_demo();
        return;
    }

    if args.len() < 3 {
        eprintln!("Usage: {} <artifact> <bundle.sigstore.json>", args[0]);
        eprintln!("       {} --demo", args[0]);
        process::exit(1);
    }

    let artifact_path = &args[1];
    let bundle_path = &args[2];

    // Read artifact
    let artifact = match fs::read(artifact_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading artifact {}: {}", artifact_path, e);
            process::exit(1);
        }
    };

    // Read bundle
    let bundle_json = match fs::read_to_string(bundle_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading bundle {}: {}", bundle_path, e);
            process::exit(1);
        }
    };

    // Parse bundle
    let bundle = match Bundle::from_json(&bundle_json) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error parsing bundle: {}", e);
            process::exit(1);
        }
    };

    // Print bundle info
    println!("Bundle Information:");
    println!("  Media Type: {}", bundle.media_type);

    match bundle.version() {
        Ok(v) => println!("  Version: {:?}", v),
        Err(e) => println!("  Version: error ({})", e),
    }

    if let Some(cert) = bundle.signing_certificate() {
        println!("  Certificate: {} bytes (base64)", cert.len());
    }

    println!(
        "  Tlog Entries: {}",
        bundle.verification_material.tlog_entries.len()
    );
    println!("  Has Inclusion Proof: {}", bundle.has_inclusion_proof());
    println!(
        "  Has Inclusion Promise: {}",
        bundle.has_inclusion_promise()
    );

    println!(
        "  Timestamps: {}",
        bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .len()
    );

    // Verify bundle structure
    println!("\nValidating bundle structure...");
    let options = ValidationOptions {
        require_inclusion_proof: bundle.has_inclusion_proof(),
        require_timestamp: false,
    };

    match validate_bundle_with_options(&bundle, &options) {
        Ok(()) => println!("  Bundle structure: VALID"),
        Err(e) => {
            eprintln!("  Bundle structure: INVALID - {}", e);
            process::exit(1);
        }
    }

    // Verify signature
    println!("\nVerifying signature...");
    let policy = VerificationPolicy::default().skip_timestamp(); // Skip timestamp for now

    match verify(&artifact, &bundle, &policy) {
        Ok(result) => {
            if result.success {
                println!("  Verification: SUCCESS");
                if let Some(time) = result.integrated_time {
                    use chrono::{DateTime, Utc};
                    if let Some(dt) = DateTime::<Utc>::from_timestamp(time, 0) {
                        println!("  Integrated Time: {}", dt);
                    }
                }
                if let Some(id) = &result.identity {
                    println!("  Identity: {}", id);
                }
                if let Some(issuer) = &result.issuer {
                    println!("  Issuer: {}", issuer);
                }
                for warning in &result.warnings {
                    println!("  Warning: {}", warning);
                }
            } else {
                eprintln!("  Verification: FAILED");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("  Verification: ERROR - {}", e);
            process::exit(1);
        }
    }

    println!("\nVerification completed successfully!");
}

fn run_demo() {
    println!("Sigstore Bundle Verification Demo\n");
    println!("=================================\n");

    // Use a real v0.3 bundle from the test fixtures
    let bundle_json = include_str!("../../sigstore-bundle/tests/fixtures/bundle_v3.json");

    let bundle = Bundle::from_json(bundle_json).expect("Failed to parse demo bundle");

    println!("Bundle Information:");
    println!("  Media Type: {}", bundle.media_type);
    println!("  Version: {:?}", bundle.version().unwrap());
    println!("  Has Inclusion Proof: {}", bundle.has_inclusion_proof());
    println!(
        "  Has Inclusion Promise: {}",
        bundle.has_inclusion_promise()
    );

    for (i, entry) in bundle.verification_material.tlog_entries.iter().enumerate() {
        println!("\n  Tlog Entry {}:", i);
        println!("    Log Index: {}", entry.log_index);
        println!(
            "    Kind: {}/{}",
            entry.kind_version.kind, entry.kind_version.version
        );
        println!("    Integrated Time: {}", entry.integrated_time);

        if let Some(proof) = &entry.inclusion_proof {
            println!("    Inclusion Proof:");
            println!("      Tree Size: {}", proof.tree_size);
            println!("      Log Index: {}", proof.log_index);
            println!("      Proof Hashes: {}", proof.hashes.len());
        }
    }

    // Validate bundle structure
    println!("\nValidating bundle structure...");
    let options = ValidationOptions {
        require_inclusion_proof: true,
        require_timestamp: false,
    };

    match validate_bundle_with_options(&bundle, &options) {
        Ok(()) => println!("  Bundle structure: VALID"),
        Err(e) => println!("  Bundle structure: INVALID - {}", e),
    }

    // For demo, we don't have the original artifact, so we'll use a dummy
    let artifact = b"demo artifact - in real use, this would be the signed file";

    // Verify with relaxed policy (no artifact hash check since we don't have original)
    let policy = VerificationPolicy::default().skip_timestamp();

    println!("\nVerifying with demo artifact...");
    match verify(artifact, &bundle, &policy) {
        Ok(result) => {
            println!(
                "  Verification: {}",
                if result.success { "SUCCESS" } else { "FAILED" }
            );
            if let Some(time) = result.integrated_time {
                use chrono::{DateTime, Utc};
                if let Some(dt) = DateTime::<Utc>::from_timestamp(time, 0) {
                    println!("  Integrated Time: {}", dt);
                }
            }
        }
        Err(e) => println!("  Verification: ERROR - {}", e),
    }

    println!("\nDemo completed!");
    println!("\nNote: Full verification requires:");
    println!("  - The original artifact that was signed");
    println!("  - Trusted root configuration (Fulcio CA, Rekor keys)");
    println!("  - Certificate chain validation");
    println!("  - DSSE signature verification");
}
