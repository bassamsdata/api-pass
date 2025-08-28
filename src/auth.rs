use anyhow::Result;

#[cfg(target_os = "macos")]
pub fn require_biometric_auth() -> Result<bool> {
    require_biometric_auth_with_output(false)
}

#[cfg(target_os = "macos")]
pub fn require_biometric_auth_silent() -> Result<bool> {
    require_biometric_auth_with_output(true)
}

#[cfg(target_os = "macos")]
fn require_biometric_auth_with_output(silent_mode: bool) -> Result<bool> {
    use std::process::Command;

    if !silent_mode {
        println!("🔐 Requesting Touch ID authentication...");
    } else {
        eprintln!("🔐 Requesting Touch ID authentication...");
    }

    // Swift script that uses LocalAuthentication framework
    let swift_script = r#"
import LocalAuthentication

let context = LAContext()
var error: NSError?

// Check if biometric authentication is available
guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
    print("BIOMETRIC_NOT_AVAILABLE")
    exit(1)
}

// Request biometric authentication
let semaphore = DispatchSemaphore(value: 0)
var authResult = false

context.evaluatePolicy(
    .deviceOwnerAuthenticationWithBiometrics,
    localizedReason: "api-pass requires authentication to access your API keys"
) { success, authenticationError in
    authResult = success
    semaphore.signal()
}

semaphore.wait()

if authResult {
    print("SUCCESS")
    exit(0)
} else {
    print("FAILED")
    exit(1)
}
"#;

    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join("api_pass_auth.swift");
    std::fs::write(&script_path, swift_script)?;

    // Compile and run the Swift script
    let compile_output = Command::new("swiftc")
        .arg(&script_path)
        .arg("-o")
        .arg(temp_dir.join("api_pass_auth"))
        .output();

    match compile_output {
        Ok(compile_result) => {
            if !compile_result.status.success() {
                println!("⚠️  Failed to compile authentication helper, falling back to password");
                return fallback_password_auth();
            }

            // Run the compiled binary
            let auth_output = Command::new(temp_dir.join("api_pass_auth"))
                .output();

            let _ = std::fs::remove_file(&script_path);
            let _ = std::fs::remove_file(temp_dir.join("api_pass_auth"));

            match auth_output {
                Ok(result) => {
                    let output_str = String::from_utf8_lossy(&result.stdout).trim().to_string();

                    match output_str.as_str() {
                        "SUCCESS" => {
                            if !silent_mode {
                                println!("✅ Touch ID authentication successful");
                            } else {
                                eprintln!("✅ Touch ID authentication successful");
                            }
                            Ok(true)
                        },
                        "BIOMETRIC_NOT_AVAILABLE" => {
                            if !silent_mode {
                                println!("⚠️  Touch ID not available, falling back to password");
                            } else {
                                eprintln!("⚠️  Touch ID not available, falling back to password");
                            }
                            fallback_password_auth()
                        },
                        _ => {
                            if !silent_mode {
                                println!("❌ Touch ID authentication failed or cancelled");
                            } else {
                                eprintln!("❌ Touch ID authentication failed or cancelled");
                            }
                            Ok(false)
                        }
                    }
                },
                Err(e) => {
                    if !silent_mode {
                        println!("⚠️  Error running authentication: {}, falling back to password", e);
                    } else {
                        eprintln!("⚠️  Error running authentication: {}, falling back to password", e);
                    }
                    fallback_password_auth()
                }
            }
        },
        Err(e) => {
            if !silent_mode {
                println!("⚠️  Swift compiler not available: {}, falling back to password", e);
            } else {
                eprintln!("⚠️  Swift compiler not available: {}, falling back to password", e);
            }
            fallback_password_auth()
        }
    }
}


fn fallback_password_auth() -> Result<bool> {
    println!("Falling back to password verification...");

    let stored_password = get_stored_master_password()?;
    let entered_password = rpassword::prompt_password("Enter master password: ")?;

    if stored_password == entered_password {
        println!("✅ Password authentication successful");
        Ok(true)
    } else {
        println!("❌ Incorrect password");
        Ok(false)
    }
}

fn get_stored_master_password() -> Result<String> {
    use keyring::Entry;
    let entry = Entry::new("api-pass", "master")?;
    Ok(entry.get_password()?)
}
