use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::{get_storage_dir, ensure_storage_dir};

// Session duration: 60 minutes
const SESSION_DURATION_MINUTES: u64 = 60;

#[derive(Serialize, Deserialize, Clone)]
pub struct SimpleSessionToken {
    pub terminal_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub authenticated: bool,
}

impl SimpleSessionToken {
    pub fn new(use_project_sessions: bool) -> Result<Self> {
        let terminal_id = generate_terminal_id(use_project_sessions);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        Ok(SimpleSessionToken {
            terminal_id,
            created_at: now,
            expires_at: now + (SESSION_DURATION_MINUTES * 60),
            authenticated: true,
        })
    }

    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > self.expires_at {
            return false;
        }

        // Note: We can't check terminal_id here because we don't know if the original
        // session was created with project_sessions flag. This is a limitation, but that's ok .
        // The session file path lookup handles the matching.

        self.authenticated
    }

    pub fn time_remaining(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.expires_at.saturating_sub(now)
    }
}

pub struct SessionManager {
    sessions_dir: PathBuf,
    use_project_sessions: bool,
}

impl SessionManager {
    pub fn new(use_project_sessions: bool) -> Result<Self> {
        let sessions_dir = get_storage_dir()?.join("sessions");
        ensure_storage_dir()?;

        if !sessions_dir.exists() {
            fs::create_dir_all(&sessions_dir)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&sessions_dir)?.permissions();
                perms.set_mode(0o700); // Owner read/write/execute only
                fs::set_permissions(&sessions_dir, perms)?;
            }
        }

        Ok(SessionManager { sessions_dir, use_project_sessions })
    }

    pub fn create_session(&self) -> Result<()> {
        let token = SimpleSessionToken::new(self.use_project_sessions)?;
        let session_file = self.get_session_file_path(&token.terminal_id);

        let session_data = serde_json::to_vec(&token)?;
        fs::write(&session_file, session_data)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&session_file)?.permissions();
            perms.set_mode(0o600); // Owner read/write only
            fs::set_permissions(&session_file, perms)?;
        }

        Ok(())
    }

    pub fn get_valid_session(&self) -> Result<Option<SimpleSessionToken>> {
        self.cleanup_expired_sessions()?;

        let terminal_id = generate_terminal_id(self.use_project_sessions);
        let session_file = self.get_session_file_path(&terminal_id);

        if !session_file.exists() {
            return Ok(None);
        }

        match fs::read(&session_file) {
            Ok(session_data) => {
                match serde_json::from_slice::<SimpleSessionToken>(&session_data) {
                    Ok(token) => {
                        if token.is_valid() {
                            Ok(Some(token))
                        } else {
                            let _ = fs::remove_file(&session_file);
                            Ok(None)
                        }
                    }
                    Err(_) => {
                        // Corrupt session file, remove it
                        let _ = fs::remove_file(&session_file);
                        Ok(None)
                    }
                }
            }
            Err(_) => Ok(None),
        }
    }

    pub fn has_valid_session(&self) -> bool {
        self.get_valid_session().unwrap_or(None).is_some()
    }

    pub fn clear_current_session(&self) -> Result<()> {
        let terminal_id = generate_terminal_id(self.use_project_sessions);
        let session_file = self.get_session_file_path(&terminal_id);

        if session_file.exists() {
            fs::remove_file(&session_file)?;
        }

        Ok(())
    }

    pub fn clear_all_sessions(&self) -> Result<()> {
        if self.sessions_dir.exists() {
            for entry in fs::read_dir(&self.sessions_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("session") {
                    let _ = fs::remove_file(path);
                }
            }
        }
        Ok(())
    }

    pub fn cleanup_expired_sessions(&self) -> Result<()> {
        if !self.sessions_dir.exists() {
            return Ok(());
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        for entry in fs::read_dir(&self.sessions_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) != Some("session") {
                continue;
            }

            // Try to load and check if expired
            if let Ok(session_data) = fs::read(&path) {
                match serde_json::from_slice::<SimpleSessionToken>(&session_data) {
                    Ok(token) => {
                        if now > token.expires_at {
                            let _ = fs::remove_file(&path);
                        }
                    }
                    Err(_) => {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }

        Ok(())
    }

    // pub fn list_active_sessions(&self) -> Result<Vec<SimpleSessionToken>> {
    //     let mut sessions = Vec::new();
    //
    //     if !self.sessions_dir.exists() {
    //         return Ok(sessions);
    //     }
    //
    //     for entry in fs::read_dir(&self.sessions_dir)? {
    //         let entry = entry?;
    //         let path = entry.path();
    //
    //         if path.extension().and_then(|s| s.to_str()) != Some("session") {
    //             continue;
    //         }
    //
    //         if let Ok(session_data) = fs::read(&path) {
    //             if let Ok(token) = serde_json::from_slice::<SimpleSessionToken>(&session_data) {
    //                 if token.is_valid() {
    //                     sessions.push(token);
    //                 }
    //             }
    //         }
    //     }
    //
    //     Ok(sessions)
    // }

    fn get_session_file_path(&self, terminal_id: &str) -> PathBuf {
        self.sessions_dir.join(format!("{}.session", terminal_id))
    }
}

// Helper functions

fn generate_terminal_id(use_project_sessions: bool) -> String {
    // Generate a clean terminal identifier from the start
    let tty_name = get_clean_tty_name();
    let session_info = get_clean_session_info(use_project_sessions);

    format!("{}_{}", tty_name, session_info)
}

fn get_clean_tty_name() -> String {
    // Try to get TTY info and convert to clean name
    if let Ok(tty) = std::env::var("TTY") {
        return clean_tty_path(&tty);
    }

    if let Ok(ssh_tty) = std::env::var("SSH_TTY") {
        return format!("ssh_{}", clean_tty_path(&ssh_tty));
    }

    // Try system call for TTY
    #[cfg(unix)]
    {
        use std::ffi::CStr;
        unsafe {
            let tty_ptr = libc::ttyname(libc::STDIN_FILENO);
            if !tty_ptr.is_null() {
                if let Ok(tty_cstr) = CStr::from_ptr(tty_ptr).to_str() {
                    return clean_tty_path(tty_cstr);
                }
            }
        }
    }

    // Clean fallback
    "local_terminal".to_string()
}

fn get_clean_session_info(use_project_sessions: bool) -> String {
    let mut session_parts = Vec::new();

    // Get session identifier and clean it
    if let Ok(term_session) = std::env::var("TERM_SESSION_ID") {
        session_parts.push(format!("session_{}", clean_identifier(&term_session)));
    } else if let Ok(ssh_conn) = std::env::var("SSH_CONNECTION") {
        // SSH_CONNECTION format: "client_ip client_port server_ip server_port"
        let parts: Vec<&str> = ssh_conn.split_whitespace().collect();
        if parts.len() >= 2 {
            session_parts.push(format!("ssh_{}_{}", clean_identifier(parts[0]), parts[1]));
        } else {
            session_parts.push("ssh_session".to_string());
        }
    } else if let Ok(_display) = std::env::var("DISPLAY") {
        session_parts.push("display_session".to_string());
    } else {
        // No specific session info found
        session_parts.push("terminal".to_string());
    }

    // Add project info if requested
    if use_project_sessions {
        if let Some(project) = get_current_project_name() {
            session_parts.push(project);
        }
    }

    // Always add username
    session_parts.push(format!("user_{}", whoami::username()));

    session_parts.join("_")
}

fn get_current_project_name() -> Option<String> {
    if let Ok(current_dir) = std::env::current_dir() {
        if let Some(dir_name) = current_dir.file_name() {
            if let Some(dir_str) = dir_name.to_str() {
                return Some(clean_identifier(dir_str));
            }
        }
    }
    None
}

fn clean_tty_path(tty_path: &str) -> String {
    // Convert TTY paths to clean names
    if tty_path.contains("not a tty") || tty_path == "not a tty" {
        return "no_tty".to_string();
    }

    // Extract meaningful part from paths like "/dev/ttys001" -> "ttys001"
     if let Some(last_part) = tty_path.rsplit('/').next() {
        if !last_part.is_empty() && last_part != "dev" {
            return clean_identifier(last_part);
        }
    }

    // Clean the whole path if no meaningful part found
    clean_identifier(tty_path)
}

fn clean_identifier(identifier: &str) -> String {
    identifier
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_token_creation() {
        let token = SimpleSessionToken::new(false).unwrap();

        assert!(!token.terminal_id.is_empty());
        assert!(token.created_at > 0);
        assert!(token.expires_at > token.created_at);
        assert!(token.authenticated);
    }

    #[test]
    fn test_session_validity() {
        let token = SimpleSessionToken::new(false).unwrap();
        assert!(token.is_valid());

        // Test expired token
        let expired_token = SimpleSessionToken {
            terminal_id: generate_terminal_id(false),
            created_at: 1000,
            expires_at: 2000, // Way in the past
            authenticated: true,
        };
        assert!(!expired_token.is_valid());
    }

    #[test]
    fn test_session_manager() {
        let manager = SessionManager::new(false).unwrap();

        // No session initially
        assert!(!manager.has_valid_session());

        // Create session
        manager.create_session().unwrap();
        assert!(manager.has_valid_session());

        // Clear session
        manager.clear_current_session().unwrap();
        assert!(!manager.has_valid_session());
    }
}
