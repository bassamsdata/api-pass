use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use anyhow::Result;

mod crypto;
mod storage;
mod auth;
mod session;

use crypto::{encrypt_data, decrypt_data, derive_key, generate_entry_salt, generate_secure_password, encrypt_data_with_password, decrypt_data_with_password};
use storage::{get_storage_path, ensure_storage_dir, load_master_salt};
use auth::{require_biometric_auth, require_biometric_auth_silent};
use session::SessionManager;

#[derive(Parser)]
#[command(name = "api-pass")]
#[command(about = "Secure CLI API key manager with biometric authentication")]
struct Cli {
    /// Use project-specific sessions (includes current directory in session)
    #[arg(long, global = true)]
    project_sessions: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set/store an API key
    Set {
        /// Service name
        service: String,
        /// API key (if not provided, will prompt)
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Show an API key (requires biometric auth)
    Show {
        service: String,
        #[arg(long)]
        key: bool,
    },
    /// List all stored services
    List,
    /// Modify an existing API key
    Modify {
        service: String,
    },
    /// Delete an API key (requires biometric auth)
    Delete {
        service: String,
    },
    /// Export all data to CSV (requires biometric auth)
    Export {
        /// Output file path
        #[arg(short, long, default_value = "api_keys_export.csv")]
        output: String,
    },
    /// Initialize the password manager
    Init,
    /// Session management
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
}

#[derive(Subcommand)]
enum SessionAction {
    Status,
    Clear,
    ClearAll,
}

#[derive(Serialize, Deserialize, Clone)]
struct ApiEntry {
    service: String,
    encrypted_key: String,
    salt: String,
    created_at: String,
    last_modified: String,
}

#[derive(Serialize, Deserialize, Default)]
struct ApiDatabase {
    entries: HashMap<String, ApiEntry>,
    master_salt: String,
}

impl ApiDatabase {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            master_salt: String::new(), // TODO: This field is now deprecated but kept for deltion
        }
    }

    fn load() -> Result<Self> {
        let storage_path = get_storage_path()?;
        if storage_path.exists() {
            let encrypted_data = fs::read(&storage_path)?;
            let master_key = get_master_key()?;
            let decrypted_data = decrypt_data(&encrypted_data, &master_key)?;
            let db: ApiDatabase = serde_json::from_slice(&decrypted_data)?;
            Ok(db)
        } else {
            Ok(Self::new())
        }
    }

    fn save(&self) -> Result<()> {
        ensure_storage_dir()?;
        let json_data = serde_json::to_vec(self)?;
        let master_key = get_master_key()?;
        let encrypted_data = encrypt_data(&json_data, &master_key)?;
        let storage_path = get_storage_path()?;
        fs::write(&storage_path, encrypted_data)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&storage_path)?.permissions();
            perms.set_mode(0o600); // Owner read/write only
            fs::set_permissions(&storage_path, perms)?;
        }

        Ok(())
    }
}

fn get_master_key() -> Result<[u8; 32]> {
    get_master_key_for_biometric_user()
}

fn get_master_key_for_biometric_user() -> Result<[u8; 32]> {
    use keyring::Entry;

    let entry = Entry::new("api-pass", "master")?;

    match entry.get_password() {
        Ok(password) => {
            // Use the stored master salt for key derivation
            let master_salt = load_master_salt()?;
            let key = derive_key(&password, &master_salt)?;
            Ok(key)
        },
        Err(_) => {
            // For biometric users, create a secure random default password
            let default_password = generate_secure_password(64);
            entry.set_password(&default_password)?;
            let master_salt = load_master_salt()?;
            let key = derive_key(&default_password, &master_salt)?;
            Ok(key)
        }
    }
}

fn get_master_key_with_prompt() -> Result<[u8; 32]> {
    use keyring::Entry;

    let entry = Entry::new("api-pass", "master")?;

    match entry.get_password() {
        Ok(password) => {
            let master_salt = load_master_salt()?;
            let key = derive_key(&password, &master_salt)?;
            Ok(key)
        },
        Err(_) => {
            // First time setup - prompt for password
            println!("Setting up api-pass for the first time...");
            let password = rpassword::prompt_password("Enter master password: ")?;
            let confirm = rpassword::prompt_password("Confirm master password: ")?;

            if password != confirm {
                anyhow::bail!("Passwords don't match!");
            }

            entry.set_password(&password)?;
            let master_salt = load_master_salt()?;
            let key = derive_key(&password, &master_salt)?;
            Ok(key)
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init => {
            println!("Initializing api-pass...");
            let _key = get_master_key_with_prompt()?;
            let db = ApiDatabase::new();
            db.save()?;
            println!("✅ api-pass initialized successfully!");
        },

        Commands::Set { service, key } => {
            let mut db = ApiDatabase::load()?;

            let api_key = match key {
                Some(k) => k.clone(),
                None => rpassword::prompt_password(format!("Enter API key for {}: ", service))?,
            };

            let salt = generate_entry_salt();
            let salt_hex = hex::encode(salt);

            // Encrypt the API key using per-entry salt for defense in depth
            let master_password = get_master_password()?;
            let encrypted_key = encrypt_data_with_password(api_key.as_bytes(), &master_password, &salt)?;

            let now = chrono::Utc::now().to_rfc3339();
            let entry = ApiEntry {
                service: service.clone(),
                encrypted_key: hex::encode(encrypted_key),
                salt: salt_hex,
                created_at: now.clone(),
                last_modified: now,
            };

            db.entries.insert(service.clone(), entry);
            db.save()?;

            println!("✅ API key for '{}' stored successfully!", service);
        },

        Commands::Show { service, key } => {
            let master_password = get_master_password_with_session(*key, cli.project_sessions)?;
            let db = ApiDatabase::load()?;

            match db.entries.get(service) {
                Some(entry) => {
                    let encrypted_data = hex::decode(&entry.encrypted_key)?;
                    let entry_salt = hex::decode(&entry.salt)?;
                    let decrypted_key = decrypt_data_with_password(&encrypted_data, &master_password, &entry_salt)?;
                    let api_key = String::from_utf8(decrypted_key)?;

                    if *key {
                        // Only output the API key for piping/scripting
                        // TODO: we still need 2>/dev/null to hide those messages, need to remove them
                        println!("{}", api_key);
                    } else {
                        // Full formatted output
                        println!("Service: {}", service);
                        println!("API Key: {}", api_key);
                        println!("Created: {}", entry.created_at);
                        println!("Last Modified: {}", entry.last_modified);
                    }
                },
                None => {
                    println!("❌ No API key found for service '{}'", service);
                }
            }
        },

        Commands::List => {
            let db = ApiDatabase::load()?;

            if db.entries.is_empty() {
                println!("No API keys stored yet.");
            } else {
                println!("Stored services:");
                for (service, entry) in &db.entries {
                    println!("  • {} (created: {})", service, entry.created_at);
                }
            }
        },

        Commands::Modify { service } => {
            let mut db = ApiDatabase::load()?;

            if !db.entries.contains_key(service) {
                println!("❌ No API key found for service '{}'", service);
                return Ok(());
            }

            let new_key = rpassword::prompt_password(format!("Enter new API key for {}: ", service))?;

            // Update the entry
            if let Some(entry) = db.entries.get_mut(service) {
                let master_password = get_master_password_with_prompt()?;
                let entry_salt = hex::decode(&entry.salt)?;
                let encrypted_key = encrypt_data_with_password(new_key.as_bytes(), &master_password, &entry_salt)?;

                entry.encrypted_key = hex::encode(encrypted_key);
                entry.last_modified = chrono::Utc::now().to_rfc3339();
            }

            db.save()?;
            println!("✅ API key for '{}' updated successfully!", service);
        },

        Commands::Delete { service } => {
            let _master_password = get_master_password_with_session(false, cli.project_sessions)?;
            let mut db = ApiDatabase::load()?;

            match db.entries.remove(service) {
                Some(_) => {
                    db.save()?;
                    println!("✅ API key for '{}' deleted successfully!", service);
                },
                None => {
                    println!("❌ No API key found for service '{}'", service);
                }
            }
        },

        Commands::Export { output } => {
            let master_password = get_master_password_with_session(false, cli.project_sessions)?;
            let db = ApiDatabase::load()?;

            let mut wtr = csv::Writer::from_path(output)?;
            wtr.write_record(["Service", "API_Key", "Created_At", "Last_Modified"])?;

            for (service, entry) in &db.entries {
                let encrypted_data = hex::decode(&entry.encrypted_key)?;
                let entry_salt = hex::decode(&entry.salt)?;
                let decrypted_key = decrypt_data_with_password(&encrypted_data, &master_password, &entry_salt)?;
                let api_key = String::from_utf8(decrypted_key)?;

                wtr.write_record([
                    service,
                    &api_key,
                    &entry.created_at,
                    &entry.last_modified,
                ])?;
            }

            wtr.flush()?;
            println!("✅ Exported {} entries to '{}'", db.entries.len(), output);
        },

        Commands::Session { action } => {
            let session_manager = SessionManager::new(cli.project_sessions)?;

            match action {
                SessionAction::Status => {
                    if let Some(session) = session_manager.get_valid_session()? {
                        let remaining_minutes = session.time_remaining() / 60;
                        println!("Active session: expires in {} minutes", remaining_minutes);
                        println!("  Terminal: {}", session.terminal_id);
                        let created_time = std::time::SystemTime::UNIX_EPOCH +
                            std::time::Duration::from_secs(session.created_at);
                        println!("  Created: {:?}", created_time);
                        if cli.project_sessions {
                            println!("  Mode: Project-specific session");
                        } else {
                            println!("  Mode: Persistent session");
                        }
                    } else {
                        println!("No active session");
                    }
                },
                SessionAction::Clear => {
                    session_manager.clear_current_session()?;
                    println!("✅ Current session cleared");
                },
                SessionAction::ClearAll => {
                    session_manager.clear_all_sessions()?;
                    println!("✅ All sessions cleared");
                },
            }
        },
    }

    Ok(())
}

// Get master password with session support
fn get_master_password_with_session(silent_mode: bool, use_project_sessions: bool) -> Result<String> {
    let session_manager = SessionManager::new(use_project_sessions)?;

    if session_manager.has_valid_session() {
        return get_master_password();
    }

    let auth_success = if silent_mode {
        require_biometric_auth_silent()?
    } else {
        require_biometric_auth()?
    };

    if !auth_success {
        anyhow::bail!("Authentication failed!");
    }

    let master_password = get_master_password()?;
    session_manager.create_session()?;
    Ok(master_password)
}

// Get master password from keyring
fn get_master_password() -> Result<String> {
    use keyring::Entry;
    let entry = Entry::new("api-pass", "master")?;
    Ok(entry.get_password()?)
}

// Get master password with prompt for new users
fn get_master_password_with_prompt() -> Result<String> {
    use keyring::Entry;
    let entry = Entry::new("api-pass", "master")?;

    match entry.get_password() {
        Ok(password) => Ok(password),
        Err(_) => {
            println!("Setting up api-pass for the first time...");
            let password = rpassword::prompt_password("Enter master password: ")?;
            let confirm = rpassword::prompt_password("Confirm master password: ")?;

            if password != confirm {
                anyhow::bail!("Passwords don't match!");
            }

            entry.set_password(&password)?;
            Ok(password)
        }
    }
}
