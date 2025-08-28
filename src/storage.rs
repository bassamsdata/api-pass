use std::fs;
use std::path::PathBuf;
use anyhow::Result;
use rand::rngs::OsRng;
use rand::RngCore;


pub fn get_storage_dir() -> Result<PathBuf> {
    let home_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;

    Ok(home_dir.join(".api-pass"))
}

pub fn get_storage_path() -> Result<PathBuf> {
    Ok(get_storage_dir()?.join("database.enc"))
}

pub fn get_salt_path() -> Result<PathBuf> {
    Ok(get_storage_dir()?.join("master.salt"))
}

pub fn ensure_storage_dir() -> Result<()> {
    let storage_dir = get_storage_dir()?;

    if !storage_dir.exists() {
        fs::create_dir_all(&storage_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&storage_dir)?.permissions();
            perms.set_mode(0o700); // Owner read/write/execute only
            fs::set_permissions(&storage_dir, perms)?;
        }
    }

    Ok(())
}

pub fn store_master_salt(salt: &[u8; 32]) -> Result<()> {
    ensure_storage_dir()?;
    let salt_path = get_salt_path()?;
    fs::write(&salt_path, salt)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&salt_path)?.permissions();
        perms.set_mode(0o600); // Owner read/write only
        fs::set_permissions(&salt_path, perms)?;
    }

    Ok(())
}

pub fn load_master_salt() -> Result<[u8; 32]> {
    let salt_path = get_salt_path()?;

    if salt_path.exists() {
        let salt_bytes = fs::read(&salt_path)?;
        if salt_bytes.len() != 32 {
            anyhow::bail!("Invalid salt file: incorrect length");
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);
        Ok(salt)
    } else {
        // Generate new salt and store it
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        store_master_salt(&salt)?;
        Ok(salt)
    }
}
