use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

use crate::wireguard::{RedactedProfile, WireGuardProfile};

const SCHEMA_VERSION: i64 = 1;
const ENCRYPTION_VERSION: i64 = 1;
const AAD: &[u8] = b"egressy-wireguard-profile-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManagedRevision {
    pub id: String,
    pub created_at_unix_ms: u64,
    pub activated_at_unix_ms: Option<u64>,
    pub active: bool,
    pub staged: bool,
    pub metadata: RedactedProfile,
}

#[derive(Clone)]
pub struct ProfileStore {
    path: Arc<PathBuf>,
    key: Arc<Zeroizing<[u8; 32]>>,
    lock: Arc<Mutex<()>>,
}

impl ProfileStore {
    pub fn open(path: impl Into<PathBuf>, key_path: &Path) -> anyhow::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let key = load_key(key_path)?;
        let store = Self {
            path: Arc::new(path),
            key: Arc::new(Zeroizing::new(key)),
            lock: Arc::new(Mutex::new(())),
        };
        let mut connection = store.connection()?;
        migrate(&mut connection)?;
        secure_database_files(&store.path)?;
        Ok(store)
    }

    fn connection(&self) -> anyhow::Result<Connection> {
        let connection = Connection::open(self.path.as_ref())?;
        connection.busy_timeout(std::time::Duration::from_secs(2))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        Ok(connection)
    }

    pub async fn revisions(&self) -> anyhow::Result<Vec<ManagedRevision>> {
        let _guard = self.lock.lock().await;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, created_at_ms, activated_at_ms, active, staged, metadata_json
             FROM wireguard_profiles ORDER BY created_at_ms DESC LIMIT 100",
        )?;
        let rows = statement.query_map([], revision_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub async fn active(&self) -> anyhow::Result<Option<(ManagedRevision, WireGuardProfile)>> {
        let _guard = self.lock.lock().await;
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT id, created_at_ms, activated_at_ms, active, staged, metadata_json,
                        nonce, ciphertext, encryption_version
                 FROM wireguard_profiles WHERE active = 1 LIMIT 1",
                [],
                |row| {
                    Ok((
                        revision_from_row(row)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(revision, nonce, ciphertext, version)| {
            self.decrypt_profile(&nonce, &ciphertext, version)
                .map(|profile| (revision, profile))
        })
        .transpose()
    }

    pub async fn load(&self, id: &str) -> anyhow::Result<Option<WireGuardProfile>> {
        validate_id(id)?;
        let _guard = self.lock.lock().await;
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT nonce, ciphertext, encryption_version FROM wireguard_profiles WHERE id = ?1",
                [id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?)),
            )
            .optional()?;
        row.map(|(nonce, ciphertext, version)| self.decrypt_profile(&nonce, &ciphertext, version))
            .transpose()
    }

    pub async fn stage(&self, mut source: Vec<u8>) -> anyhow::Result<ManagedRevision> {
        let profile = match WireGuardProfile::parse(&source) {
            Ok(profile) => profile,
            Err(error) => {
                source.zeroize();
                return Err(error.into());
            }
        };
        let metadata = profile.redacted(None);
        let mut nonce = [0_u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new((&**self.key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &source,
                    aad: AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("profile encryption failed"));
        source.zeroize();
        let ciphertext = ciphertext?;
        let now = crate::runtime::unix_ms();
        let mut random = [0_u8; 12];
        rand::rng().fill_bytes(&mut random);
        let id = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let revision = ManagedRevision {
            id: id.clone(),
            created_at_unix_ms: now,
            activated_at_unix_ms: None,
            active: false,
            staged: true,
            metadata,
        };
        let metadata_json = serde_json::to_string(&revision.metadata)?;
        let _guard = self.lock.lock().await;
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO wireguard_profiles
             (id, created_at_ms, active, staged, metadata_json, nonce, ciphertext, encryption_version)
             VALUES (?1, ?2, 0, 1, ?3, ?4, ?5, ?6)",
            params![id, to_i64(now), metadata_json, nonce.as_slice(), ciphertext, ENCRYPTION_VERSION],
        )?;
        secure_database_files(&self.path)?;
        Ok(revision)
    }

    pub async fn activate(&self, id: &str) -> anyhow::Result<ManagedRevision> {
        validate_id(id)?;
        let now = crate::runtime::unix_ms();
        let _guard = self.lock.lock().await;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        if transaction.query_row(
            "SELECT COUNT(*) FROM wireguard_profiles WHERE id = ?1",
            [id],
            |row| row.get::<_, i64>(0),
        )? != 1
        {
            bail!("managed profile revision does not exist");
        }
        transaction.execute("UPDATE wireguard_profiles SET active = 0", [])?;
        transaction.execute(
            "UPDATE wireguard_profiles SET active = 1, staged = 0, activated_at_ms = ?2 WHERE id = ?1",
            params![id, to_i64(now)],
        )?;
        transaction.commit()?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, created_at_ms, activated_at_ms, active, staged, metadata_json
             FROM wireguard_profiles WHERE id = ?1",
                [id],
                revision_from_row,
            )
            .map_err(Into::into)
    }

    pub async fn delete_inactive(&self, id: &str) -> anyhow::Result<()> {
        validate_id(id)?;
        let _guard = self.lock.lock().await;
        let connection = self.connection()?;
        let changed = connection.execute(
            "DELETE FROM wireguard_profiles WHERE id = ?1 AND active = 0",
            [id],
        )?;
        if changed != 1 {
            bail!("only an existing inactive revision may be deleted");
        }
        Ok(())
    }

    fn decrypt_profile(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        version: i64,
    ) -> anyhow::Result<WireGuardProfile> {
        if version != ENCRYPTION_VERSION || nonce.len() != 24 {
            bail!("stored profile uses an unsupported encryption format");
        }
        let cipher = XChaCha20Poly1305::new((&**self.key).into());
        let mut plaintext = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("stored profile cannot be decrypted with the configured key")
            })?;
        let result = WireGuardProfile::parse(&plaintext).map_err(Into::into);
        plaintext.zeroize();
        result
    }
}

fn load_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    let metadata = fs::metadata(path).context("reading profile storage key metadata")?;
    if !metadata.is_file() || metadata.len() > 1024 {
        bail!("profile storage key must be a regular file no larger than 1 KiB");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("profile storage key must not be readable by group or others");
        }
    }
    let mut encoded = fs::read(path)?;
    while encoded.last().is_some_and(u8::is_ascii_whitespace) {
        encoded.pop();
    }
    let decoded = STANDARD
        .decode(&encoded)
        .context("profile storage key must be base64-encoded")?;
    encoded.zeroize();
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("profile storage key must decode to exactly 32 bytes"))?;
    Ok(key)
}

fn migrate(connection: &mut Connection) -> anyhow::Result<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        bail!("profile database schema is newer than supported");
    }
    if version == 0 {
        connection.execute_batch(
            "CREATE TABLE wireguard_profiles (
                id TEXT PRIMARY KEY,
                created_at_ms INTEGER NOT NULL,
                activated_at_ms INTEGER,
                active INTEGER NOT NULL CHECK (active IN (0, 1)),
                staged INTEGER NOT NULL CHECK (staged IN (0, 1)),
                metadata_json TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                encryption_version INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE UNIQUE INDEX one_active_wireguard_profile
                ON wireguard_profiles (active) WHERE active = 1;
             PRAGMA user_version = 1;",
        )?;
    }
    Ok(())
}

fn revision_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ManagedRevision> {
    let metadata: String = row.get(5)?;
    let metadata = serde_json::from_str(&metadata).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            metadata.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(ManagedRevision {
        id: row.get(0)?,
        created_at_unix_ms: from_i64(row.get(1)?),
        activated_at_unix_ms: row.get::<_, Option<i64>>(2)?.map(from_i64),
        active: row.get(3)?,
        staged: row.get(4)?,
        metadata,
    })
}

fn secure_database_files(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for candidate in [
            path.to_path_buf(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            if candidate.exists() {
                fs::set_permissions(candidate, fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    Ok(())
}

fn validate_id(id: &str) -> anyhow::Result<()> {
    if id.len() != 24 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid managed profile revision id");
    }
    Ok(())
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn from_i64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const PROFILE: &str = "[Interface]\nPrivateKey = fake-private\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n[Peer]\nPublicKey = fake-public\nPresharedKey = fake-psk\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n";

    fn key(path: &Path, byte: u8) {
        fs::write(path, STANDARD.encode([byte; 32])).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[tokio::test]
    async fn stores_only_ciphertext_and_redacted_metadata() {
        let temp = tempfile::TempDir::new().unwrap();
        let key_path = temp.path().join("key");
        key(&key_path, 7);
        let database = temp.path().join("profiles.sqlite3");
        let store = ProfileStore::open(&database, &key_path).unwrap();
        let staged = store.stage(PROFILE.as_bytes().to_vec()).await.unwrap();
        assert!(!serde_json::to_string(&staged)
            .unwrap()
            .contains("fake-private"));
        store.activate(&staged.id).await.unwrap();
        let (_, profile) = store.active().await.unwrap().unwrap();
        assert!(profile.render().contains("fake-private"));
        let bytes = fs::read(&database).unwrap();
        let database_text = String::from_utf8_lossy(&bytes);
        assert!(!database_text.contains("fake-private"));
        assert!(!database_text.contains("fake-psk"));
    }

    #[tokio::test]
    async fn incorrect_key_fails_without_plaintext_fallback() {
        let temp = tempfile::TempDir::new().unwrap();
        let key_path = temp.path().join("key");
        key(&key_path, 7);
        let database = temp.path().join("profiles.sqlite3");
        let store = ProfileStore::open(&database, &key_path).unwrap();
        let staged = store.stage(PROFILE.as_bytes().to_vec()).await.unwrap();
        store.activate(&staged.id).await.unwrap();
        key(&key_path, 8);
        let wrong = ProfileStore::open(&database, &key_path).unwrap();
        assert!(wrong.active().await.is_err());
    }

    #[test]
    fn missing_or_unprotected_key_is_rejected() {
        let temp = tempfile::TempDir::new().unwrap();
        assert!(ProfileStore::open(temp.path().join("db"), &temp.path().join("missing")).is_err());
        let key_path = temp.path().join("key");
        fs::write(&key_path, STANDARD.encode([0_u8; 32])).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ProfileStore::open(temp.path().join("db"), &key_path).is_err());
    }
}
