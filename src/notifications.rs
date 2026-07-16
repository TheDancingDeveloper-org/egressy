use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context};
use omnihook::{
    DiscordPayloadBuilder, GenericWebhookPayloadBuilder, SlackPayloadBuilder,
    TelegramPayloadBuilder, WebhookConfig,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use url::Url;

use crate::{
    domain::{CheckStatus, Transition},
    runtime::SharedHistory,
};

const QUEUE_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationProvider {
    #[default]
    Discord,
    Slack,
    Telegram,
    Generic,
}

impl NotificationProvider {
    pub fn as_database(self) -> &'static str {
        match self {
            Self::Discord => "discord",
            Self::Slack => "slack",
            Self::Telegram => "telegram",
            Self::Generic => "generic",
        }
    }

    pub fn from_database(value: &str) -> Self {
        match value {
            "slack" => Self::Slack,
            "telegram" => Self::Telegram,
            "generic" => Self::Generic,
            _ => Self::Discord,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct NotificationSettings {
    pub enabled: bool,
    pub provider: NotificationProvider,
    pub webhook_url: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub hmac_secret: Option<String>,
    pub timeout_seconds: u32,
    pub rtt_threshold_ms: f64,
    pub alert_stack_started: bool,
    pub alert_vpn_disconnected: bool,
    pub alert_vpn_reconnected: bool,
    pub alert_rtt_above_threshold: bool,
    pub alert_diagnostic_failed: bool,
    pub updated_at_unix_ms: u64,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: NotificationProvider::Discord,
            webhook_url: None,
            telegram_chat_id: None,
            hmac_secret: None,
            timeout_seconds: 10,
            rtt_threshold_ms: 100.0,
            alert_stack_started: true,
            alert_vpn_disconnected: true,
            alert_vpn_reconnected: true,
            alert_rtt_above_threshold: true,
            alert_diagnostic_failed: true,
            updated_at_unix_ms: 0,
        }
    }
}

impl NotificationSettings {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(1..=30).contains(&self.timeout_seconds) {
            bail!("timeout_seconds must be between 1 and 30");
        }
        if !self.rtt_threshold_ms.is_finite()
            || self.rtt_threshold_ms < 1.0
            || self.rtt_threshold_ms > 60_000.0
        {
            bail!("rtt_threshold_ms must be between 1 and 60000");
        }
        if self.enabled || self.webhook_url.is_some() {
            let raw = self
                .webhook_url
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .context("webhook_url is required when notifications are enabled")?;
            let url = Url::parse(raw).context("webhook_url is invalid")?;
            if url.scheme() != "https" || url.host_str().is_none() {
                bail!("webhook_url must use HTTPS and include a hostname");
            }
        }
        if self.provider == NotificationProvider::Telegram
            && (self.enabled || self.webhook_url.is_some())
            && self
                .telegram_chat_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            bail!("telegram_chat_id is required for Telegram");
        }
        if self.provider != NotificationProvider::Generic && self.hmac_secret.is_some() {
            bail!("hmac_secret is supported only for generic webhooks");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationSettingsInput {
    pub enabled: bool,
    pub provider: NotificationProvider,
    pub webhook_url: String,
    #[serde(default)]
    pub telegram_chat_id: String,
    #[serde(default)]
    pub hmac_secret: String,
    pub timeout_seconds: u32,
    pub rtt_threshold_ms: f64,
    pub alert_stack_started: bool,
    pub alert_vpn_disconnected: bool,
    pub alert_vpn_reconnected: bool,
    pub alert_rtt_above_threshold: bool,
    pub alert_diagnostic_failed: bool,
}

impl NotificationSettingsInput {
    pub fn merge(self, current: &NotificationSettings) -> NotificationSettings {
        let optional = |value: String| (!value.trim().is_empty()).then(|| value.trim().to_owned());
        let telegram_chat_id = (self.provider == NotificationProvider::Telegram)
            .then(|| optional(self.telegram_chat_id).or_else(|| current.telegram_chat_id.clone()))
            .flatten();
        let hmac_secret = (self.provider == NotificationProvider::Generic)
            .then(|| optional(self.hmac_secret).or_else(|| current.hmac_secret.clone()))
            .flatten();
        NotificationSettings {
            enabled: self.enabled,
            provider: self.provider,
            webhook_url: optional(self.webhook_url).or_else(|| current.webhook_url.clone()),
            telegram_chat_id,
            hmac_secret,
            timeout_seconds: self.timeout_seconds,
            rtt_threshold_ms: self.rtt_threshold_ms,
            alert_stack_started: self.alert_stack_started,
            alert_vpn_disconnected: self.alert_vpn_disconnected,
            alert_vpn_reconnected: self.alert_vpn_reconnected,
            alert_rtt_above_threshold: self.alert_rtt_above_threshold,
            alert_diagnostic_failed: self.alert_diagnostic_failed,
            updated_at_unix_ms: crate::runtime::unix_ms(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NotificationSettingsView {
    pub enabled: bool,
    pub provider: NotificationProvider,
    pub destination: Option<String>,
    pub webhook_configured: bool,
    pub telegram_chat_id_configured: bool,
    pub hmac_secret_configured: bool,
    pub timeout_seconds: u32,
    pub rtt_threshold_ms: f64,
    pub alert_stack_started: bool,
    pub alert_vpn_disconnected: bool,
    pub alert_vpn_reconnected: bool,
    pub alert_rtt_above_threshold: bool,
    pub alert_diagnostic_failed: bool,
    pub updated_at_unix_ms: u64,
}

impl From<&NotificationSettings> for NotificationSettingsView {
    fn from(settings: &NotificationSettings) -> Self {
        Self {
            enabled: settings.enabled,
            provider: settings.provider,
            destination: settings.webhook_url.as_deref().and_then(mask_destination),
            webhook_configured: settings.webhook_url.is_some(),
            telegram_chat_id_configured: settings.telegram_chat_id.is_some(),
            hmac_secret_configured: settings.hmac_secret.is_some(),
            timeout_seconds: settings.timeout_seconds,
            rtt_threshold_ms: settings.rtt_threshold_ms,
            alert_stack_started: settings.alert_stack_started,
            alert_vpn_disconnected: settings.alert_vpn_disconnected,
            alert_vpn_reconnected: settings.alert_vpn_reconnected,
            alert_rtt_above_threshold: settings.alert_rtt_above_threshold,
            alert_diagnostic_failed: settings.alert_diagnostic_failed,
            updated_at_unix_ms: settings.updated_at_unix_ms,
        }
    }
}

fn mask_destination(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    Some(format!("{}://{}/…", url.scheme(), url.host_str()?))
}

#[derive(Clone, Debug)]
struct Notification {
    title: String,
    body: String,
    idempotency_key: String,
}

#[derive(Clone)]
pub struct NotificationManager {
    settings: Arc<RwLock<NotificationSettings>>,
    sender: mpsc::Sender<Notification>,
}

impl NotificationManager {
    pub async fn start(history: SharedHistory) -> Self {
        let initial = if let Some(store) = history.read().await.clone() {
            match store.notification_settings().await {
                Ok(settings) => settings,
                Err(error) => {
                    tracing::warn!(%error, "notification settings are unavailable; alerts start disabled");
                    NotificationSettings::default()
                }
            }
        } else {
            NotificationSettings::default()
        };
        let settings = Arc::new(RwLock::new(initial));
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        tokio::spawn(delivery_worker(settings.clone(), receiver));
        Self { settings, sender }
    }

    #[cfg(test)]
    fn test_manager(settings: NotificationSettings) -> (Self, mpsc::Receiver<Notification>) {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        (
            Self {
                settings: Arc::new(RwLock::new(settings)),
                sender,
            },
            receiver,
        )
    }

    pub async fn view(&self) -> NotificationSettingsView {
        NotificationSettingsView::from(&*self.settings.read().await)
    }

    pub async fn settings(&self) -> NotificationSettings {
        self.settings.read().await.clone()
    }

    pub async fn update(
        &self,
        input: NotificationSettingsInput,
        history: &SharedHistory,
    ) -> anyhow::Result<NotificationSettingsView> {
        let current = self.settings().await;
        let settings = input.merge(&current);
        settings.validate()?;
        let store = history
            .read()
            .await
            .clone()
            .context("notification settings require enabled local persistence")?;
        store.save_notification_settings(settings.clone()).await?;
        *self.settings.write().await = settings;
        Ok(self.view().await)
    }

    pub async fn test(&self) -> anyhow::Result<()> {
        let settings = self.settings().await;
        settings.validate()?;
        if settings.webhook_url.is_none() {
            bail!("configure a webhook destination first");
        }
        send_with_settings(
            &settings,
            &Notification {
                title: "Egressy test notification".into(),
                body: "Omnihook delivery is configured successfully.".into(),
                idempotency_key: format!("egressy-test-{}", crate::runtime::unix_ms()),
            },
        )
        .await
    }

    async fn enqueue(&self, notification: Notification) {
        if self.sender.try_send(notification).is_err() {
            tracing::warn!("notification queue is full or unavailable; alert was dropped");
        }
    }

    pub async fn stack_started(&self) {
        let settings = self.settings().await;
        if settings.enabled && settings.alert_stack_started {
            self.enqueue(Notification {
                title: "Stack Started".into(),
                body: "Egressy started and installed its fail-closed gateway policy.".into(),
                idempotency_key: format!("stack-started-{}", crate::runtime::unix_ms()),
            })
            .await;
        }
    }

    pub async fn transition(&self, transition: &Transition) {
        let settings = self.settings().await;
        if !settings.enabled {
            return;
        }
        let notification = if transition.component == "wireguard.handshake"
            && transition.from_status != CheckStatus::Failed
            && transition.to_status == CheckStatus::Failed
            && settings.alert_vpn_disconnected
        {
            Some((
                "VPN Disconnected",
                "The WireGuard handshake is missing or stale.",
            ))
        } else if transition.component == "wireguard.handshake"
            && transition.from_status == CheckStatus::Failed
            && transition.to_status == CheckStatus::Healthy
            && settings.alert_vpn_reconnected
        {
            Some((
                "VPN Reconnected",
                "A recent WireGuard handshake was observed again.",
            ))
        } else if transition.component != "wireguard.handshake"
            && transition.from_status != CheckStatus::Failed
            && transition.to_status == CheckStatus::Failed
            && settings.alert_diagnostic_failed
        {
            let title = format!("{} diagnostic failed", transition.component);
            self.enqueue(Notification {
                title,
                body: transition.safe_message.clone(),
                idempotency_key: format!("transition-{}", transition.sequence),
            })
            .await;
            return;
        } else {
            None
        };
        if let Some((title, body)) = notification {
            self.enqueue(Notification {
                title: title.into(),
                body: body.into(),
                idempotency_key: format!("transition-{}", transition.sequence),
            })
            .await;
        }
    }

    pub async fn rtt_sample(&self, rtt_ms: f64, was_above: &mut bool) {
        let settings = self.settings().await;
        let above = rtt_ms > settings.rtt_threshold_ms;
        if settings.enabled && settings.alert_rtt_above_threshold && above && !*was_above {
            self.enqueue(Notification {
                title: "VPN RTT threshold exceeded".into(),
                body: format!(
                    "Underlay RTT to the active VPN endpoint is {:.1} ms, above the configured {:.1} ms threshold.",
                    rtt_ms, settings.rtt_threshold_ms
                ),
                idempotency_key: format!("rtt-high-{}", crate::runtime::unix_ms()),
            })
            .await;
        }
        *was_above = above;
    }
}

async fn delivery_worker(
    settings: Arc<RwLock<NotificationSettings>>,
    mut receiver: mpsc::Receiver<Notification>,
) {
    while let Some(notification) = receiver.recv().await {
        let settings = settings.read().await.clone();
        if send_with_settings(&settings, &notification).await.is_err() {
            // Omnihook/reqwest errors may include the destination URL. The path
            // can contain a webhook credential, so never interpolate it here.
            tracing::warn!("Omnihook notification delivery failed");
        }
    }
}

async fn send_with_settings(
    settings: &NotificationSettings,
    notification: &Notification,
) -> anyhow::Result<()> {
    let url = Url::parse(
        settings
            .webhook_url
            .as_deref()
            .context("webhook destination is not configured")?,
    )?;
    let mut config = WebhookConfig::new(url)
        .with_timeout(Duration::from_secs(u64::from(settings.timeout_seconds)));
    if settings.provider == NotificationProvider::Generic {
        if let Some(secret) = settings.hmac_secret.as_deref() {
            config = config.with_secret(secret);
        }
    }
    let client = config.build().context("building Omnihook client")?;
    match settings.provider {
        NotificationProvider::Discord => {
            client
                .notify(
                    &notification.title,
                    &notification.body,
                    &DiscordPayloadBuilder,
                )
                .await?
        }
        NotificationProvider::Slack => {
            client
                .notify(
                    &notification.title,
                    &notification.body,
                    &SlackPayloadBuilder,
                )
                .await?
        }
        NotificationProvider::Telegram => {
            client
                .notify(
                    &notification.title,
                    &notification.body,
                    &TelegramPayloadBuilder {
                        chat_id: settings.telegram_chat_id.clone().unwrap_or_default(),
                        disable_web_preview: true,
                    },
                )
                .await?
        }
        NotificationProvider::Generic => {
            client
                .notify_with_key(
                    &notification.title,
                    &notification.body,
                    &GenericWebhookPayloadBuilder,
                    Some(&notification.idempotency_key),
                )
                .await?
        }
    }
    Ok(())
}

pub async fn monitor_transitions(
    manager: NotificationManager,
    publisher: crate::control::StatePublisher,
) {
    let mut events = publisher.subscribe_events();
    loop {
        match events.recv().await {
            Ok(transition) => manager.transition(&transition).await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::warn!(skipped, "notification transition monitor lagged")
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_insecure_destinations_and_invalid_thresholds() {
        let settings = NotificationSettings {
            enabled: true,
            webhook_url: Some("http://example.com/hook".into()),
            ..NotificationSettings::default()
        };
        assert!(settings.validate().is_err());
        let settings = NotificationSettings {
            enabled: true,
            webhook_url: Some("https://example.com/hook".into()),
            rtt_threshold_ms: f64::NAN,
            ..NotificationSettings::default()
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn public_view_masks_webhook_secrets() {
        let settings = NotificationSettings {
            webhook_url: Some("https://discord.com/api/webhooks/123/secret".into()),
            hmac_secret: Some("also-secret".into()),
            ..NotificationSettings::default()
        };
        let serialized = serde_json::to_string(&NotificationSettingsView::from(&settings)).unwrap();
        assert!(serialized.contains("https://discord.com/…"));
        assert!(!serialized.contains("123/secret"));
        assert!(!serialized.contains("also-secret"));
    }

    #[tokio::test]
    async fn transition_hooks_distinguish_disconnect_reconnect_and_diagnostics() {
        let (manager, mut receiver) = NotificationManager::test_manager(NotificationSettings {
            enabled: true,
            webhook_url: Some("https://example.com/hook".into()),
            ..NotificationSettings::default()
        });
        for (sequence, component, from_status, to_status) in [
            (
                1,
                "wireguard.handshake",
                CheckStatus::Healthy,
                CheckStatus::Failed,
            ),
            (
                2,
                "wireguard.handshake",
                CheckStatus::Failed,
                CheckStatus::Healthy,
            ),
            (
                3,
                "client_path.dns",
                CheckStatus::Healthy,
                CheckStatus::Failed,
            ),
        ] {
            manager
                .transition(&Transition {
                    sequence,
                    timestamp_unix_ms: sequence,
                    component: component.into(),
                    from_status,
                    to_status,
                    reason_code: "test".into(),
                    safe_message: "safe detail".into(),
                    recovery_attempt: None,
                })
                .await;
        }
        assert_eq!(receiver.recv().await.unwrap().title, "VPN Disconnected");
        assert_eq!(receiver.recv().await.unwrap().title, "VPN Reconnected");
        assert_eq!(
            receiver.recv().await.unwrap().title,
            "client_path.dns diagnostic failed"
        );
    }

    #[tokio::test]
    async fn rtt_hook_fires_only_when_crossing_above_threshold() {
        let (manager, mut receiver) = NotificationManager::test_manager(NotificationSettings {
            enabled: true,
            webhook_url: Some("https://example.com/hook".into()),
            rtt_threshold_ms: 50.0,
            ..NotificationSettings::default()
        });
        let mut above = false;
        manager.rtt_sample(40.0, &mut above).await;
        manager.rtt_sample(60.0, &mut above).await;
        manager.rtt_sample(70.0, &mut above).await;
        manager.rtt_sample(30.0, &mut above).await;
        manager.rtt_sample(55.0, &mut above).await;
        assert_eq!(
            receiver.recv().await.unwrap().title,
            "VPN RTT threshold exceeded"
        );
        assert_eq!(
            receiver.recv().await.unwrap().title,
            "VPN RTT threshold exceeded"
        );
        assert!(receiver.try_recv().is_err());
    }
}
