use std::{path::Path, sync::Arc};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::{
    config::{Config, ProfileSource},
    enforcement::EnforcementCoordinator,
    profiles::{ManagedRevision, ProfileStore},
    wireguard::{ApplyKind, ProfileError, RedactedProfile, WireGuardProfile},
};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileLifecycle {
    #[default]
    Unconfigured,
    Validating,
    Applying,
    Active,
    Degraded,
    ApplyFailed,
    Recovering,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProfileManagementStatus {
    pub lifecycle: ProfileLifecycle,
    pub source: String,
    pub source_mutable: bool,
    pub active_revision: Option<String>,
    pub active: Option<RedactedProfile>,
    pub revisions: Vec<ManagedRevision>,
    pub last_apply: Option<ApplyResult>,
    pub management_available: bool,
    pub mutation_authorized: bool,
    pub ipv4_only: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplyResult {
    pub revision: Option<String>,
    pub classification: ApplyKind,
    pub rolled_back: bool,
    pub safe_message: String,
}

#[derive(Clone)]
pub struct ProfileManager {
    config: Config,
    store: Option<ProfileStore>,
    enforcement: EnforcementCoordinator,
    active: Arc<RwLock<Option<ActiveProfile>>>,
    status: Arc<RwLock<ProfileManagementStatus>>,
    transaction: Arc<Mutex<()>>,
    dns_upstream: tokio::sync::watch::Sender<Option<std::net::SocketAddr>>,
    selected_source: Arc<RwLock<ProfileSource>>,
}

#[derive(Clone)]
struct ActiveProfile {
    revision: Option<String>,
    profile: WireGuardProfile,
}

impl ProfileManager {
    pub fn new(
        config: Config,
        store: Option<ProfileStore>,
        enforcement: EnforcementCoordinator,
        active_profile: Option<WireGuardProfile>,
        dns_upstream: tokio::sync::watch::Sender<Option<std::net::SocketAddr>>,
    ) -> Self {
        let source_mutable = config.wireguard.source == ProfileSource::GuiManaged;
        let selected_source = config.wireguard.source;
        let lifecycle = if active_profile.is_some() {
            ProfileLifecycle::Active
        } else {
            ProfileLifecycle::Unconfigured
        };
        let active_metadata = active_profile
            .as_ref()
            .map(|profile| profile.redacted(None));
        Self {
            status: Arc::new(RwLock::new(ProfileManagementStatus {
                lifecycle,
                source: match config.wireguard.source {
                    ProfileSource::Mounted => "mounted",
                    ProfileSource::GuiManaged => "gui_managed",
                }
                .to_owned(),
                source_mutable,
                active: active_metadata,
                management_available: true,
                mutation_authorized: config.wireguard.admin_token_path.is_some(),
                ipv4_only: true,
                ..ProfileManagementStatus::default()
            })),
            config,
            store,
            enforcement,
            active: Arc::new(RwLock::new(active_profile.map(|profile| ActiveProfile {
                revision: None,
                profile,
            }))),
            transaction: Arc::new(Mutex::new(())),
            dns_upstream,
            selected_source: Arc::new(RwLock::new(selected_source)),
        }
    }

    pub async fn initialize(&self) -> anyhow::Result<()> {
        if let Some(store) = &self.store {
            let revisions = store.revisions().await?;
            let mut status = self.status.write().await;
            status.revisions = revisions;
            if self.config.wireguard.source == ProfileSource::GuiManaged {
                if let Some(revision_id) = status
                    .revisions
                    .iter()
                    .find(|revision| revision.active)
                    .map(|revision| revision.id.clone())
                {
                    status.active_revision = Some(revision_id.clone());
                    if let Some(active) = self.active.write().await.as_mut() {
                        active.revision = Some(revision_id);
                        self.publish_dns(Some(&active.profile));
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn status(&self) -> ProfileManagementStatus {
        self.status.read().await.clone()
    }

    pub async fn has_active_profile(&self) -> bool {
        self.active.read().await.is_some()
    }

    pub async fn configured_peer(&self) -> Option<crate::vpn_server::ConfiguredPeer> {
        self.active.read().await.as_ref().and_then(|active| {
            crate::vpn_server::parse_wireguard_profile(&active.profile.render()).ok()
        })
    }

    pub async fn validate(&self, source: &[u8]) -> Result<RedactedProfile, ProfileError> {
        {
            let mut status = self.status.write().await;
            status.lifecycle = ProfileLifecycle::Validating;
        }
        let active = self.active.read().await.clone();
        let result = WireGuardProfile::parse(source)
            .map(|profile| profile.redacted(active.as_ref().map(|active| &active.profile)));
        self.status.write().await.lifecycle = if active.is_some() {
            ProfileLifecycle::Active
        } else {
            ProfileLifecycle::Unconfigured
        };
        result
    }

    pub async fn stage(&self, source: Vec<u8>) -> anyhow::Result<ManagedRevision> {
        let store = self
            .store
            .as_ref()
            .context("GUI-managed profile storage is unavailable")?;
        let _guard = self.transaction.lock().await;
        let revision = store.stage(source).await?;
        self.status.write().await.revisions = store.revisions().await?;
        Ok(revision)
    }

    pub async fn stage_mounted_profile(&self) -> anyhow::Result<ManagedRevision> {
        let profile = crate::runtime::load_mounted_profile(&self.config)
            .await?
            .context("the mounted profile is absent")?;
        self.stage(profile.render_source().into_bytes()).await
    }

    pub async fn stage_edit(
        &self,
        input: crate::wireguard::StructuredProfileInput,
    ) -> anyhow::Result<ManagedRevision> {
        if *self.selected_source.read().await != ProfileSource::GuiManaged {
            bail!("mounted profile source is read-only");
        }
        let store = self.store.as_ref().context("profile storage unavailable")?;
        let _guard = self.transaction.lock().await;
        let active = self
            .active
            .read()
            .await
            .clone()
            .context("an active profile is required for structured editing")?;
        let candidate = active.profile.edit(input)?;
        let revision = store.stage(candidate.render_source().into_bytes()).await?;
        self.status.write().await.revisions = store.revisions().await?;
        Ok(revision)
    }

    pub async fn apply(&self, revision_id: &str) -> anyhow::Result<ApplyResult> {
        if *self.selected_source.read().await != ProfileSource::GuiManaged {
            bail!("mounted profile source is read-only");
        }
        let store = self
            .store
            .as_ref()
            .context("GUI-managed profile storage is unavailable")?;
        let _guard = self.transaction.lock().await;
        let candidate = store
            .load(revision_id)
            .await?
            .context("managed profile revision does not exist")?;
        crate::runtime::validate_profile_capabilities(&self.config, &candidate)?;
        let previous = self.active.read().await.clone();
        let classification = previous
            .as_ref()
            .map_or(ApplyKind::TunnelRecycle, |active| {
                active.profile.diff(&candidate)
            });
        self.status.write().await.lifecycle = ProfileLifecycle::Applying;
        self.enforcement.reconcile_base().await?;

        let result = async {
            self.apply_candidate(
                &candidate,
                classification,
                previous.as_ref().map(|active| &active.profile),
            )
            .await?;
            self.verify_tunnel_evidence().await
        }
        .await;
        match result {
            Ok(()) => {
                let revision = match store.activate(revision_id).await {
                    Ok(revision) => revision,
                    Err(error) => {
                        let restored = if let Some(previous) = &previous {
                            self.recycle_and_reconcile(&previous.profile, Some(&candidate))
                                .await
                                .is_ok()
                        } else {
                            crate::runtime::wireguard_down(&self.config).await;
                            false
                        };
                        let mut status = self.status.write().await;
                        status.lifecycle = ProfileLifecycle::ApplyFailed;
                        status.last_apply = Some(ApplyResult {
                            revision: previous.as_ref().and_then(|active| active.revision.clone()),
                            classification,
                            rolled_back: restored,
                            safe_message: if restored {
                                "Revision activation failed; the previous profile was restored"
                            } else {
                                "Revision activation failed; enrolled traffic remains blocked"
                            }
                            .to_owned(),
                        });
                        return Err(error.context("committing the active profile revision"));
                    }
                };
                *self.active.write().await = Some(ActiveProfile {
                    revision: Some(revision.id.clone()),
                    profile: candidate.clone(),
                });
                self.publish_dns(Some(&candidate));
                let result = ApplyResult {
                    revision: Some(revision.id.clone()),
                    classification,
                    rolled_back: false,
                    safe_message: match classification {
                        ApplyKind::NoChange => "The selected profile was already active",
                        ApplyKind::DnsReload => "DNS configuration and tunnel service routes were reloaded",
                        ApplyKind::SyncConf | ApplyKind::SyncConfAndRoutes => "WireGuard configuration was hot-applied",
                        ApplyKind::TunnelRecycle => "The WireGuard interface was recycled without restarting application containers",
                    }.to_owned(),
                };
                let mut status = self.status.write().await;
                status.lifecycle = ProfileLifecycle::Active;
                status.active_revision = Some(revision.id);
                status.active = Some(candidate.redacted(Some(&candidate)));
                status.revisions = store.revisions().await?;
                status.last_apply = Some(result.clone());
                Ok(result)
            }
            Err(error) => {
                let restored = if let Some(previous) = &previous {
                    let restored = self
                        .recycle_and_reconcile(&previous.profile, Some(&candidate))
                        .await
                        .is_ok();
                    if restored {
                        self.publish_dns(Some(&previous.profile));
                    }
                    restored
                } else {
                    crate::runtime::wireguard_down(&self.config).await;
                    false
                };
                let result = ApplyResult {
                    revision: previous.as_ref().and_then(|active| active.revision.clone()),
                    classification,
                    rolled_back: restored,
                    safe_message: if restored {
                        "Profile application failed; the previous active profile was restored"
                    } else {
                        "Profile application failed; enrolled traffic remains blocked"
                    }
                    .to_owned(),
                };
                let mut status = self.status.write().await;
                status.lifecycle = ProfileLifecycle::ApplyFailed;
                status.last_apply = Some(result);
                Err(error.context("applying managed WireGuard profile"))
            }
        }
    }

    pub async fn delete(&self, revision_id: &str) -> anyhow::Result<()> {
        let store = self.store.as_ref().context("profile storage unavailable")?;
        let _guard = self.transaction.lock().await;
        store.delete_inactive(revision_id).await?;
        self.status.write().await.revisions = store.revisions().await?;
        Ok(())
    }

    pub async fn activate_source(&self, source: ProfileSource) -> anyhow::Result<ApplyResult> {
        let _guard = self.transaction.lock().await;
        let (revision, candidate) = match source {
            ProfileSource::Mounted => (
                None,
                crate::runtime::load_mounted_profile(&self.config)
                    .await?
                    .context("the mounted profile is absent")?,
            ),
            ProfileSource::GuiManaged => {
                let store = self.store.as_ref().context("profile storage unavailable")?;
                let (revision, profile) = store
                    .active()
                    .await?
                    .context("no active GUI-managed revision exists")?;
                (Some(revision.id), profile)
            }
        };
        crate::runtime::validate_profile_capabilities(&self.config, &candidate)?;
        let previous = self.active.read().await.clone();
        let classification = previous
            .as_ref()
            .map_or(ApplyKind::TunnelRecycle, |active| {
                active.profile.diff(&candidate)
            });
        self.status.write().await.lifecycle = ProfileLifecycle::Applying;
        self.enforcement.reconcile_base().await?;
        let applied = async {
            self.apply_candidate(
                &candidate,
                classification,
                previous.as_ref().map(|active| &active.profile),
            )
            .await?;
            self.verify_tunnel_evidence().await
        }
        .await;
        if let Err(error) = applied {
            let restored = if let Some(previous) = &previous {
                self.recycle_and_reconcile(&previous.profile, Some(&candidate))
                    .await
                    .is_ok()
            } else {
                crate::runtime::wireguard_down(&self.config).await;
                false
            };
            let mut status = self.status.write().await;
            status.lifecycle = ProfileLifecycle::ApplyFailed;
            status.last_apply = Some(ApplyResult {
                revision: previous.and_then(|profile| profile.revision),
                classification,
                rolled_back: restored,
                safe_message: if restored {
                    "Source activation failed; the previous profile was restored"
                } else {
                    "Source activation failed; enrolled traffic remains blocked"
                }
                .to_owned(),
            });
            return Err(error.context("activating WireGuard profile source"));
        }
        *self.active.write().await = Some(ActiveProfile {
            revision: revision.clone(),
            profile: candidate.clone(),
        });
        *self.selected_source.write().await = source;
        self.publish_dns(Some(&candidate));
        let result = ApplyResult {
            revision: revision.clone(),
            classification,
            rolled_back: false,
            safe_message: "The selected profile source was activated transactionally".to_owned(),
        };
        let mut status = self.status.write().await;
        status.lifecycle = ProfileLifecycle::Active;
        status.source = match source {
            ProfileSource::Mounted => "mounted",
            ProfileSource::GuiManaged => "gui_managed",
        }
        .to_owned();
        status.source_mutable = source == ProfileSource::GuiManaged;
        status.active_revision = revision;
        status.active = Some(candidate.redacted(Some(&candidate)));
        status.last_apply = Some(result.clone());
        Ok(result)
    }

    pub async fn recover(&self) -> anyhow::Result<()> {
        let _guard = self.transaction.lock().await;
        let active = self
            .active
            .read()
            .await
            .clone()
            .context("no active profile is available for recovery")?;
        self.status.write().await.lifecycle = ProfileLifecycle::Recovering;
        let result = self.recycle(&active.profile).await;
        self.status.write().await.lifecycle = if result.is_ok() {
            ProfileLifecycle::Active
        } else {
            ProfileLifecycle::Degraded
        };
        result
    }

    pub async fn mark_degraded(&self) {
        if self.has_active_profile().await {
            self.status.write().await.lifecycle = ProfileLifecycle::Degraded;
        }
    }

    pub async fn mark_active(&self) {
        if self.has_active_profile().await {
            self.status.write().await.lifecycle = ProfileLifecycle::Active;
        }
    }

    async fn apply_candidate(
        &self,
        candidate: &WireGuardProfile,
        classification: ApplyKind,
        previous: Option<&WireGuardProfile>,
    ) -> anyhow::Result<()> {
        let previous_dns = previous.map_or_else(Vec::new, WireGuardProfile::ipv4_dns);
        match classification {
            ApplyKind::NoChange => Ok(()),
            ApplyKind::DnsReload => {
                crate::runtime::reconcile_gateway_routes(
                    &self.config,
                    &previous_dns,
                    &candidate.ipv4_dns(),
                )
                .await
            }
            ApplyKind::SyncConf | ApplyKind::SyncConfAndRoutes => {
                self.syncconf(candidate).await?;
                crate::runtime::reconcile_gateway_routes(
                    &self.config,
                    &previous_dns,
                    &candidate.ipv4_dns(),
                )
                .await?;
                Ok(())
            }
            ApplyKind::TunnelRecycle => self.recycle_and_reconcile(candidate, previous).await,
        }
    }

    async fn syncconf(&self, profile: &WireGuardProfile) -> anyhow::Result<()> {
        let path = Path::new("/run/egressy")
            .join(format!("{}.sync.conf", self.config.wireguard.interface));
        tokio::fs::write(&path, profile.render_syncconf()).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
        }
        let result = crate::runtime::command(
            "wg",
            &[
                "syncconf",
                &self.config.wireguard.interface,
                path.to_str().context("syncconf path is not UTF-8")?,
            ],
        )
        .await;
        let _ = tokio::fs::remove_file(path).await;
        result
    }

    async fn recycle(&self, profile: &WireGuardProfile) -> anyhow::Result<()> {
        crate::runtime::wireguard_down(&self.config).await;
        crate::runtime::wireguard_up(&self.config, profile).await
    }

    async fn recycle_and_reconcile(
        &self,
        profile: &WireGuardProfile,
        previous: Option<&WireGuardProfile>,
    ) -> anyhow::Result<()> {
        self.recycle(profile).await?;
        crate::runtime::reconcile_gateway_routes(
            &self.config,
            &previous.map_or_else(Vec::new, WireGuardProfile::ipv4_dns),
            &profile.ipv4_dns(),
        )
        .await
    }

    async fn verify_tunnel_evidence(&self) -> anyhow::Result<()> {
        let interface = self.config.wireguard.interface.clone();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let present = tokio::fs::metadata(format!("/sys/class/net/{interface}"))
                    .await
                    .is_ok();
                let inspectable = if present {
                    tokio::process::Command::new("wg")
                        .args(["show", &interface, "latest-handshakes"])
                        .output()
                        .await
                        .is_ok_and(|output| output.status.success())
                } else {
                    false
                };
                if inspectable {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        })
        .await
        .context("timed out waiting for bounded WireGuard interface evidence")??;
        Ok(())
    }

    fn publish_dns(&self, profile: Option<&WireGuardProfile>) {
        let upstream = match self.config.dns.upstream.source {
            crate::config::DnsUpstreamSource::Profile => profile
                .and_then(|profile| profile.ipv4_dns().into_iter().next())
                .map(|address| std::net::SocketAddr::new(address.into(), 53)),
            crate::config::DnsUpstreamSource::Explicit => self
                .config
                .dns
                .upstream
                .addresses
                .first()
                .and_then(|address| address.parse().ok()),
        };
        self.dns_upstream.send_replace(upstream);
    }
}
