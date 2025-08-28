# API Password Manager CLI

A secure CLI tool for managing API keys with biometric authentication on macOS and password fallback on Linux.

## Features

- ✅ **Secure Storage**: AES-256-GCM encryption with Argon2 key derivation
- ✅ **Biometric Auth**: Touch ID/Face ID integration on macOS
- ✅ **Cross-Platform**: macOS (with biometric) and Linux (password fallback)
- ✅ **CLI Interface**: Simple, intuitive command-line interface
- ✅ **Master Password**: Stored securely in system keychain
- ✅ **Export**: CSV export functionality with authentication
- ✅ **Session Management**: Persistent sessions with biometric authentication

## Installation

### Prerequisites
- Rust (install from https://rustup.rs/)
- macOS 10.12+ (for biometric features) or Linux

### Build Steps

1. **Create Project Structure**:
```bash
cargo new api-pass
cd api-pass
```

2. **Replace `Cargo.toml`** with the provided configuration

3. **Create Source Files**:
```bash
mkdir src
# Copy main.rs to src/main.rs
# Copy crypto.rs to src/crypto.rs
# Copy storage.rs to src/storage.rs
# Copy auth.rs to src/auth.rs
```

4. **Add Missing Dependencies**:
```bash
cargo add hex chrono --features chrono/serde
```

5. **Build**:
```bash
# Development build
cargo build

# Optimized release build
cargo build --release
```

6. **Install Globally** (optional):
```bash
cargo install --path .
```

## Usage

### Initialize (First Time)
```bash
api-pass init
# You'll be prompted to set a master password
```

### Store API Keys
```bash
# Interactive prompt for API key
api-pass set openai

# Provide API key directly
api-pass set anthropic --key sk-ant-api-key-here

# Alias for convenience
api-pass set github-token
```

### View API Keys (Requires Biometric Auth on macOS)
```bash
api-pass show openai
# On macOS: Touch ID/Face ID prompt
# On Linux: Master password prompt
```

### List All Services
```bash
api-pass list
```

### Modify Existing Keys
```bash
api-pass modify openai
```

### Delete Keys (Requires Biometric Auth)
```bash
api-pass delete openai
```

### Export to CSV (Requires Biometric Auth)
```bash
# Default filename
api-pass export

# Custom filename
api-pass export --output my_api_keys.csv
```

## Security Features

### Encryption
- **AES-256-GCM**: Industry-standard authenticated encryption
- **Argon2**: Memory-hard password hashing for key derivation
- **Random Salts**: Each entry uses unique salts
- **Secure Random**: OS-provided cryptographically secure randomness

### Authentication
- **macOS**: Touch ID/Face ID via Security Framework
- **Linux**: Master password verification
- **Keychain Integration**: Master password stored in system keychain

### Storage
- **Local Only**: All data stored locally in `~/.api-pass/`
- **Encrypted Database**: All data encrypted at rest
- **Restricted Permissions**: Directory permissions set to 700 (owner only)

## File Structure

```
~/.api-pass/
└── database.enc  # Encrypted database file
```

## Platform-Specific Notes

### macOS
- Biometric authentication uses the Security Framework
- Touch ID/Face ID prompts for sensitive operations
- Master password stored in macOS Keychain

### Linux
- Falls back to master password authentication
- Uses system keyring for password storage
- All core functionality available

## Development

### Adding New Features
- `main.rs`: CLI interface and command handling
- `crypto.rs`: Encryption/decryption operations
- `storage.rs`: File system operations
- `auth.rs`: Authentication (biometric + password)
- `session.rs`: Session management and storage

### Testing
```bash
cargo test
```

### Debug Build
```bash
RUST_LOG=debug cargo run -- [command]
```

## Troubleshooting

### "Command not found"
- Ensure `~/.cargo/bin` is in your PATH
- Or use `cargo run -- [command]` instead

### Permission Denied
- Check that `~/.api-pass/` has correct permissions (700)
- Run: `chmod 700 ~/.api-pass`

### Biometric Auth Not Working (macOS)
- Ensure Touch ID/Face ID is enabled in System Preferences
- Try running with `sudo` if necessary
- Check Console.app for Security Framework errors

### Keychain Issues
- Reset with: `rm -rf ~/.api-pass/` (⚠️ destroys all data)
- Re-run `api-pass init`

## License

This project is provided as-is for educational and personal use.
