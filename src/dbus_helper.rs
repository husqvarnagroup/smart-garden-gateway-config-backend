// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Wi-Fi management through wpa_supplicant's D-Bus interface.

use anyhow::{bail, Context, Result};
use dbus::arg::{cast, Get, PropMap, RefArg, Variant};
use dbus::nonblock::stdintf::org_freedesktop_dbus::Properties;
use dbus::nonblock::{Proxy, SyncConnection};
use dbus::Path;
use lazy_static::lazy_static;
use pbkdf2::pbkdf2_hmac;
use serde::Serialize;
use sha1::Sha1;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, warn};

use crate::wifiapi::{Config, KeyMgmt};

const WPA_SUPPLICANT_DEST: &str = "fi.w1.wpa_supplicant1";
const WPA_SUPPLICANT_ROOT: &str = "/fi/w1/wpa_supplicant1";
const WPA_SUPPLICANT_INTERFACE: &str = "fi.w1.wpa_supplicant1.Interface";
const WPA_SUPPLICANT_BSS: &str = "fi.w1.wpa_supplicant1.BSS";
const WPA_SUPPLICANT_NETWORK: &str = "fi.w1.wpa_supplicant1.Network";

/// How long to wait for a newly configured network to be associated.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the interface may stay disconnected before the attempt is given up.
const STUCK_TIMEOUT: Duration = Duration::from_secs(15);

/// How wpa_supplicant is asked to scan: `"passive"` or `"active"`.
///
/// A passive scan listens for beacons. An active scan sends probe requests and
/// usually finds more access points. Neither reveals the SSID of a hidden
/// network. That would need a directed probe with the SSID in the `SSIDs` argument.
const SCAN_TYPE: &str = "passive";

/// Fallback when wpa_supplicant's `ScanInterval` cannot be read.
const DEFAULT_SCAN_INTERVAL: i32 = 5;

/// Upper bound for `ScanInterval`, which is configurable and signed.
const MAX_SCAN_INTERVAL: i32 = 30;

/// How often the `Scanning` property is checked while waiting for a scan.
const SCAN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How long `Scanning == false` is treated as "the scan has not started yet"
/// rather than "the scan is done", right after triggering one.
const SCAN_START_GRACE_PERIOD: Duration = Duration::from_secs(1);

type OwnedObjectPath = Path<'static>;

/// The Wi-Fi configuration was valid, but the gateway could not associate with
/// the network (wrong key, access point out of range, ...).
#[derive(Debug)]
pub struct ConnectionFailed {
    pub state: String,
}

impl std::fmt::Display for ConnectionFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Connection could not be established. Current state: {}",
            self.state
        )
    }
}

impl std::error::Error for ConnectionFailed {}

#[derive(PartialEq, Debug, Serialize)]
pub struct Network {
    pub ssid: String,
    pub security: Security,
    pub signal: f32,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize)]
pub enum Security {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "WPA-PSK")]
    Wpapsk,
    #[serde(rename = "unsupported")]
    Unsupported,
}

/// Turns wpa_supplicant's `ScanInterval` into the timeout for waiting on a scan.
fn scan_timeout_from_interval(interval: i32) -> Duration {
    Duration::from_secs(interval.clamp(1, MAX_SCAN_INTERVAL) as u64 + 1)
}

/// Deduplicates networks by SSID and security, keeping the strongest signal, then
/// sorts them by signal strength, descending.
fn dedup_and_sort_networks(networks: impl IntoIterator<Item = Network>) -> Vec<Network> {
    let mut networks_deduped: HashMap<(String, Security), Network> = HashMap::new();
    for n in networks {
        let key = (n.ssid.clone(), n.security.clone());
        let signal = networks_deduped.get(&key).map(|n| n.signal);
        if signal.is_none() || signal.unwrap() < n.signal {
            networks_deduped.insert(key, n);
        }
    }

    let mut networks_sorted: Vec<Network> = networks_deduped.into_values().collect();
    networks_sorted.sort_unstable_by(|a, b| {
        b.signal
            .partial_cmp(&a.signal)
            .unwrap_or(Ordering::Less)
            .then_with(|| a.ssid.cmp(&b.ssid))
    });
    networks_sorted
}

pub(crate) struct WpaDbusHelper {
    dbus_connection: Arc<SyncConnection>,
    interface_name: String,
}

/// The system bus connection, shared by all requests.
///
/// `generation` increases on every successful connect. It lets the task
/// watching for a lost connection tell whether it is invalidating its own
/// connection or a newer one set up in the meantime.
#[derive(Default)]
struct SystemBus {
    generation: u64,
    connection: Option<Arc<SyncConnection>>,
}

impl SystemBus {
    /// Forgets the connection of the given generation, if it is still the
    /// current one. Returns whether the generation was the current one.
    fn invalidate(&mut self, generation: u64) -> bool {
        if self.generation != generation {
            return false;
        }

        self.connection = None;
        true
    }
}

lazy_static! {
    static ref SYSTEM_BUS: AsyncMutex<SystemBus> = AsyncMutex::new(SystemBus::default());
}

/// Returns the shared system bus connection, connecting on first use.
async fn system_bus() -> Result<Arc<SyncConnection>> {
    let mut bus = SYSTEM_BUS.lock().await;

    if let Some(connection) = bus.connection.as_ref() {
        return Ok(connection.clone());
    }

    debug!("connecting to the system bus");
    let (resource, connection) =
        dbus_tokio::connection::new_system_sync().context("Failed to connect to system bus")?;

    bus.generation += 1;
    bus.connection = Some(connection.clone());
    let generation = bus.generation;

    // Drop the cached connection once it is lost, so that the next request
    // reconnects instead of failing forever.
    tokio::spawn(async move {
        let err = resource.await;
        warn!("Lost D-Bus system bus connection: {}", err);

        if !SYSTEM_BUS.lock().await.invalidate(generation) {
            debug!("system bus was reconnected already, keeping it");
        }
    });

    info!("Connected to the system bus");
    Ok(connection)
}

impl WpaDbusHelper {
    pub(crate) async fn new_with_system_bus(
        interface_name: impl Into<String>,
    ) -> Result<WpaDbusHelper> {
        Ok(WpaDbusHelper {
            dbus_connection: system_bus().await?,
            interface_name: interface_name.into(),
        })
    }

    async fn get_dbus_property<T>(&self, path: &str, interface: &str, property: &str) -> Result<T>
    where
        T: for<'a> Get<'a> + 'static,
    {
        debug!("getting property {}.{}", interface, property);
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            path,
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );

        let value = proxy.get(interface, property).await.context(format!(
            "Failed to get property {}.{} on {}",
            interface, property, path
        ))?;

        debug!("property {}.{} retrieved", interface, property);
        Ok(value)
    }

    async fn get_wifi_interface_paths(&self) -> Result<Vec<OwnedObjectPath>> {
        self.get_dbus_property(WPA_SUPPLICANT_ROOT, WPA_SUPPLICANT_DEST, "Interfaces")
            .await
    }

    async fn get_interface_name(&self, interface_path: &OwnedObjectPath) -> Result<String> {
        self.get_dbus_property(interface_path.as_ref(), WPA_SUPPLICANT_INTERFACE, "Ifname")
            .await
    }

    async fn get_wifi_interface_path_by_name(
        &self,
        interface_name: &str,
    ) -> Result<Option<OwnedObjectPath>> {
        debug!("looking for interface {}", interface_name);
        let paths = self.get_wifi_interface_paths().await?;

        for p in paths {
            let name = self.get_interface_name(&p).await?;
            if name == interface_name {
                info!("Found interface {} at path {}", interface_name, p);
                return Ok(Some(p));
            }
        }

        debug!("interface {} not found", interface_name);
        Ok(None)
    }

    pub async fn get_configured_ssid(&self) -> Result<Option<Config>> {
        debug!("retrieving configured ssid");
        let path = self
            .get_wifi_interface_path_by_name(&self.interface_name)
            .await?;
        match path {
            Some(p) => {
                let config = self.get_configured_ssid_from_object_path(&p).await;
                debug!("configured ssid: {:?}", config.as_ref().map(|c| &c.ssid));
                Ok(config)
            }
            None => Ok(None),
        }
    }

    async fn get_configured_ssid_from_object_path(
        &self,
        interface_path: &OwnedObjectPath,
    ) -> Option<Config> {
        for network_path in self.get_candidate_network_paths(interface_path).await {
            let Some(network_props) = self.get_network_properties(&network_path).await else {
                continue;
            };
            if let Some(config) = self.extract_config_from_network_properties(&network_props) {
                return Some(config);
            }
        }

        debug!("no network configuration found");
        None
    }

    /// Networks to check when reporting the configured Wi-Fi, most relevant first.
    async fn get_candidate_network_paths(
        &self,
        interface_path: &OwnedObjectPath,
    ) -> Vec<OwnedObjectPath> {
        let mut paths = Vec::new();

        if let Some(current) = self.get_current_network_path(interface_path).await {
            paths.push(current);
        }

        match self.get_all_networks(interface_path).await {
            Ok(networks) => {
                for network in networks {
                    if !paths.contains(&network) {
                        paths.push(network);
                    }
                }
            }
            Err(e) => debug!("failed to get configured networks: {}", e),
        }

        paths
    }

    async fn get_current_network_path(
        &self,
        interface_path: &OwnedObjectPath,
    ) -> Option<OwnedObjectPath> {
        debug!("getting current network path");
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            interface_path.clone(),
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );

        let path: OwnedObjectPath = proxy
            .get(WPA_SUPPLICANT_INTERFACE, "CurrentNetwork")
            .await
            .ok()?;

        if path == "/" {
            debug!("no current network configured");
            None
        } else {
            debug!("current network: {}", path);
            Some(path)
        }
    }

    async fn get_network_properties(&self, network_path: &OwnedObjectPath) -> Option<PropMap> {
        debug!("getting network properties for {}", network_path);
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            network_path.clone(),
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );

        proxy.get_all(WPA_SUPPLICANT_NETWORK).await.map_or_else(
            |_| {
                info!("Failed to get network properties");
                None
            },
            Some,
        )
    }

    fn extract_config_from_network_properties(&self, props: &PropMap) -> Option<Config> {
        let properties_value = props.get("Properties")?;
        let inner_props = Self::variant_as_prop_map(properties_value)?;
        let ssid_value = inner_props.get("ssid")?;
        let ssid_str = Self::variant_as_string(ssid_value)?;

        let ssid = if ssid_str.starts_with('"') {
            ssid_str.trim_matches('"').to_string()
        } else {
            Self::convert_wpas_ssid_hex(&ssid_str).unwrap_or_else(|_| {
                info!("Failed to decode SSID hex: {}", ssid_str);
                ssid_str
            })
        };
        if ssid.is_empty() {
            info!("SSID is empty, ignoring");
            return None;
        }

        let key_mgmt = inner_props
            .get("key_mgmt")
            .and_then(Self::variant_as_string)
            .map(|s: String| {
                if s.contains("WPA-PSK") {
                    KeyMgmt::Wpapsk
                } else {
                    KeyMgmt::None
                }
            })
            .unwrap_or(KeyMgmt::None);

        Some(Config {
            ssid,
            key_mgmt,
            psk: String::new(),
        })
    }

    fn variant_as_string(value: &Variant<Box<dyn RefArg + 'static>>) -> Option<String> {
        value
            .0
            .as_str()
            .map(std::string::ToString::to_string)
            .or_else(|| cast::<String>(&*value.0).cloned())
    }

    fn variant_as_prop_map<'a>(
        value: &'a Variant<Box<dyn RefArg + 'static>>,
    ) -> Option<&'a PropMap> {
        cast::<PropMap>(&*value.0)
    }

    fn variant_as_u8_vec(value: &Variant<Box<dyn RefArg + 'static>>) -> Option<Vec<u8>> {
        cast::<Vec<u8>>(&*value.0).cloned().or_else(|| {
            value
                .0
                .as_iter()
                .map(|iter| iter.filter_map(|v| v.as_u64().map(|n| n as u8)).collect())
        })
    }

    fn variant_as_i16(value: &Variant<Box<dyn RefArg + 'static>>) -> Option<i16> {
        cast::<i16>(&*value.0)
            .copied()
            .or_else(|| value.0.as_i64().map(|v| v as i16))
    }

    fn variant_as_string_vec(value: &Variant<Box<dyn RefArg + 'static>>) -> Option<Vec<String>> {
        cast::<Vec<String>>(&*value.0).cloned().or_else(|| {
            value.0.as_iter().map(|iter| {
                iter.filter_map(|v| v.as_str().map(std::string::ToString::to_string))
                    .collect()
            })
        })
    }

    fn convert_wpas_ssid_hex(hex_str: &str) -> Result<String> {
        if hex_str.len() % 2 != 0 {
            anyhow::bail!("Hex string has odd length");
        }

        let bytes: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .context("Failed to parse hex string")?;

        String::from_utf8(bytes).context("Invalid UTF-8 in hex-decoded SSID")
    }

    /// Scans for available networks.
    pub(crate) async fn scan(&self) -> Result<Vec<Network>> {
        self.scan_internal(&self.interface_name).await
    }

    async fn scan_internal(&self, interface_name: &str) -> Result<Vec<Network>> {
        debug!("starting wifi scan on {}", interface_name);
        let interface_path = self
            .get_wifi_interface_path_by_name(interface_name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface_name))?;

        let scan_timeout = self.get_scan_timeout(&interface_path).await;

        if self.is_scanning(&interface_path).await? {
            // This is a user-initiated refresh, so wait for the running scan to
            // finish instead of returning stale results.
            debug!("scan already in progress");
        } else {
            debug!("triggering scan");
            self.trigger_scan(&interface_path).await?;
        }

        self.wait_for_scan(&interface_path, scan_timeout).await;

        let bss_paths = self.get_bss_paths(&interface_path).await?;
        debug!("found {} bss entries", bss_paths.len());
        let all_bsss = self.fetch_all_bss_properties(&bss_paths).await;

        let networks = all_bsss.iter().filter_map(Self::convert_bss_to_ssid);
        let ssids = dedup_and_sort_networks(networks);
        debug!("scan complete, {} unique networks", ssids.len());

        Ok(ssids)
    }

    /// How long to wait for a scan to finish.
    async fn get_scan_timeout(&self, interface_path: &OwnedObjectPath) -> Duration {
        let interval = self
            .get_dbus_property::<i32>(
                interface_path.as_ref(),
                WPA_SUPPLICANT_INTERFACE,
                "ScanInterval",
            )
            .await
            .unwrap_or(DEFAULT_SCAN_INTERVAL);

        scan_timeout_from_interval(interval)
    }

    /// Waits until wpa_supplicant reports that it is no longer scanning.
    ///
    /// A scan that does not finish in time is not an error: the BSS list already
    /// kept by wpa_supplicant is still returned, only possibly missing the most
    /// recent results.
    async fn wait_for_scan(&self, interface_path: &OwnedObjectPath, timeout: Duration) {
        let start = tokio::time::Instant::now();
        let deadline = start + timeout;
        let mut seen_scanning = false;

        loop {
            match self.is_scanning(interface_path).await {
                Ok(true) => seen_scanning = true,
                Ok(false) => {
                    // Right after triggering a scan, `Scanning` may still read
                    // `false` from before it started. Treat that as "not done"
                    // until the scan was seen running, or the grace period passes.
                    if seen_scanning || start.elapsed() >= SCAN_START_GRACE_PERIOD {
                        debug!("scan finished after {:?}", start.elapsed());
                        return;
                    }
                }
                Err(e) => {
                    debug!("failed to get scanning state: {}", e);
                    return;
                }
            }

            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "Scan did not finish within {:?}, returning the known networks",
                    timeout
                );
                return;
            }

            tokio::time::sleep(SCAN_POLL_INTERVAL).await;
        }
    }

    async fn is_scanning(&self, interface_path: &OwnedObjectPath) -> Result<bool> {
        self.get_dbus_property::<bool>(
            interface_path.as_ref(),
            WPA_SUPPLICANT_INTERFACE,
            "Scanning",
        )
        .await
    }

    async fn trigger_scan(&self, interface_path: &OwnedObjectPath) -> Result<()> {
        let scan_args: HashMap<&str, Variant<Box<dyn RefArg + 'static>>> = [(
            "Type",
            Variant(Box::new(String::from(SCAN_TYPE)) as Box<dyn RefArg + 'static>),
        )]
        .into_iter()
        .collect();

        debug!("calling dbus Scan method");
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            interface_path.clone(),
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );

        proxy
            .method_call::<(), _, _, _>(WPA_SUPPLICANT_INTERFACE, "Scan", (scan_args,))
            .await
            .context("Failed to trigger scan")?;

        debug!("scan triggered");
        Ok(())
    }

    async fn get_bss_paths(
        &self,
        interface_path: &OwnedObjectPath,
    ) -> Result<Vec<OwnedObjectPath>> {
        self.get_dbus_property(interface_path.as_ref(), WPA_SUPPLICANT_INTERFACE, "BSSs")
            .await
    }

    async fn fetch_all_bss_properties(&self, bss_paths: &[OwnedObjectPath]) -> Vec<PropMap> {
        let mut all_bsss = Vec::new();
        for bss_path in bss_paths {
            let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
                WPA_SUPPLICANT_DEST,
                bss_path.clone(),
                Duration::from_secs(10),
                self.dbus_connection.clone(),
            );
            if let Ok(props) = proxy.get_all(WPA_SUPPLICANT_BSS).await {
                all_bsss.push(props);
            }
        }
        all_bsss
    }

    fn extract_ssid_bytes(bss: &PropMap) -> Vec<u8> {
        bss.get("SSID")
            .and_then(Self::variant_as_u8_vec)
            .unwrap_or_default()
    }

    fn convert_bss_to_ssid(bss: &PropMap) -> Option<Network> {
        let ssid_bytes = Self::extract_ssid_bytes(bss);
        if ssid_bytes.is_empty() {
            return None;
        }

        let ssid_str = String::from_utf8(ssid_bytes).ok()?;
        if ssid_str.is_empty() {
            return None;
        }

        let signal = Self::extract_signal(bss);
        let security = Self::extract_security(bss);

        Some(Network {
            ssid: ssid_str,
            security,
            signal,
        })
    }

    fn extract_signal(bss: &PropMap) -> f32 {
        bss.get("Signal")
            .and_then(Self::variant_as_i16)
            .map(|v| v as f32)
            .unwrap_or(0.0)
    }

    fn extract_security(bss: &PropMap) -> Security {
        let mut security_found = false;
        let mut security: Option<Security> = None;

        // Check WPA first
        if let Some(sec) = Self::check_key_mgmt(bss, "WPA") {
            security_found = true;
            if sec == "WPA-PSK" {
                security = Some(Security::Wpapsk);
            }
        }

        // Check RSN if WPA-PSK not found yet
        if security.is_none() {
            if let Some(sec) = Self::check_key_mgmt(bss, "RSN") {
                security_found = true;
                if sec == "WPA-PSK" {
                    security = Some(Security::Wpapsk);
                }
            }
        }

        // Return the final security value
        if security_found && security.is_none() {
            Security::Unsupported
        } else if security.is_none() {
            Security::None
        } else {
            security.unwrap()
        }
    }

    fn check_key_mgmt(bss: &PropMap, field: &str) -> Option<String> {
        let field_value = bss.get(field)?;
        let field_dict = Self::variant_as_prop_map(field_value)?;
        let keymgmt_value = field_dict.get("KeyMgmt")?;
        let keymgmt_array = Self::variant_as_string_vec(keymgmt_value)?;

        if keymgmt_array.is_empty() {
            // No KeyMgmt array means unsupported security.
            return Some("unsupported".to_string());
        }

        if keymgmt_array.contains(&"wpa-psk".to_string()) {
            Some("WPA-PSK".to_string())
        } else {
            Some("unsupported".to_string())
        }
    }

    pub(crate) async fn configure(&self, config: &Config) -> Result<()> {
        debug!("configuring network: {}", config.ssid);
        let interface_path = self
            .get_wifi_interface_path_by_name(&self.interface_name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Interface {} not found", self.interface_name))?;

        let old_network = self.get_current_network_obj(&interface_path).await?;
        if old_network.is_none() {
            debug!("no current network configured");
        }

        // Leave the old, inactive network alone until the new one is known to
        // work: while merely disconnected (access point out of range, wrong key),
        // the stored network is still what this gateway reports, and removing it
        // up front would lose it for a new one that may fail to connect.

        let new_network = self.add_network(&interface_path, config).await?;

        debug!("selecting new network");
        self.select_network_without_reassociate(&interface_path, &new_network)
            .await?;

        info!("New network configured, waiting for connection");

        // Uses polling on `State` instead of waiting for a `PropertiesChanged` signal, for simplicity.
        match self
            .wait_for_connection(&interface_path, CONNECT_TIMEOUT)
            .await
        {
            Ok(_) => {
                info!("Connection to new network succeeded");

                // The new network works, so any other stored network is a leftover
                // from an earlier configuration. Removing it only now, rather than
                // before the attempt, kept the old configuration as a fallback for
                // as long as it might still be needed.
                self.remove_other_networks(&interface_path, &new_network)
                    .await;

                self.save_config(&interface_path).await?;

                info!("Configuration done");
                Ok(())
            }
            Err(e) => {
                error!("Connection to new network failed: {}", e);

                // Rollback: revert to old network first, then remove the new one
                if let Some(old) = old_network {
                    info!("Reverting back to old network");
                    if let Err(e) = self
                        .select_network_without_reassociate(&interface_path, &old)
                        .await
                    {
                        error!("Failed to revert to old network: {}", e);
                    }
                }

                // Remove the failed new network
                if let Err(remove_err) = self.remove_network(&interface_path, &new_network).await {
                    error!(
                        "Failed to remove new network during rollback: {}",
                        remove_err
                    );
                }

                let state = self
                    .get_interface_state(&interface_path)
                    .await
                    .unwrap_or_else(|_| "unknown".to_string());
                Err(ConnectionFailed { state }.into())
            }
        }
    }

    pub(crate) async fn deactivate_wifi(&self) -> Result<()> {
        debug!("deactivating wifi");
        let interface_path = self
            .get_wifi_interface_path_by_name(&self.interface_name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Interface {} not found", self.interface_name))?;

        if self
            .get_current_network_obj(&interface_path)
            .await?
            .is_some()
        {
            debug!("disconnecting from network");
            if let Err(e) = self.disconnect(&interface_path).await {
                debug!("disconnect failed (may not be connected): {}", e);
            }
        }

        // Remove every configured network, not just the current one.
        let networks = self.get_all_networks(&interface_path).await?;
        if networks.is_empty() {
            debug!("no network configured, nothing to deactivate");
            return Ok(());
        }

        debug!("removing {} network configuration(s)", networks.len());
        let mut failed = Vec::new();
        for network in &networks {
            if let Err(e) = self.remove_network(&interface_path, network).await {
                error!("Failed to remove network {}: {}", network, e);
                failed.push(network.to_string());
            }
        }

        self.save_config(&interface_path).await?;

        if !failed.is_empty() {
            bail!(
                "Failed to remove network configuration(s): {}",
                failed.join(", ")
            );
        }

        info!("WiFi deactivated and configuration removed");
        Ok(())
    }

    async fn get_current_network_obj(
        &self,
        interface_path: &OwnedObjectPath,
    ) -> Result<Option<OwnedObjectPath>> {
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            interface_path.clone(),
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );
        let path: OwnedObjectPath = proxy
            .get(WPA_SUPPLICANT_INTERFACE, "CurrentNetwork")
            .await?;

        if path == "/" {
            Ok(None)
        } else {
            Ok(Some(path))
        }
    }

    async fn get_all_networks(
        &self,
        interface_path: &OwnedObjectPath,
    ) -> Result<Vec<OwnedObjectPath>> {
        self.get_dbus_property(
            interface_path.as_ref(),
            WPA_SUPPLICANT_INTERFACE,
            "Networks",
        )
        .await
    }

    /// Removes every configured network except `keep`.
    ///
    /// Best effort: a leftover that cannot be removed is logged, not treated as a
    /// failure, since the configuration has already succeeded.
    async fn remove_other_networks(
        &self,
        interface_path: &OwnedObjectPath,
        keep: &OwnedObjectPath,
    ) {
        let networks = match self.get_all_networks(interface_path).await {
            Ok(networks) => networks,
            Err(e) => {
                warn!("Could not enumerate networks to clean up: {}", e);
                return;
            }
        };

        for network in networks.iter().filter(|n| *n != keep) {
            debug!("removing leftover network {}", network);
            if let Err(e) = self.remove_network(interface_path, network).await {
                warn!("Failed to remove leftover network {}: {}", network, e);
            }
        }
    }

    /// Derives a PSK from a passphrase, using PBKDF2-HMAC-SHA1 (IEEE 802.11i).
    fn derive_psk(passphrase: &str, ssid: &str) -> Vec<u8> {
        let mut derived = vec![0u8; 32];
        pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut derived);
        derived
    }

    /// The value to send as the `psk` network property.
    ///
    /// A 64-character PSK is the pre-shared key itself, hex-encoded, and must be
    /// sent as raw bytes: sending it as a string would make wpa_supplicant derive
    /// a key from it as if it were a passphrase, and the gateway would never
    /// connect. A shorter passphrase (8-63 characters) is derived into a PSK with
    /// PBKDF2-HMAC-SHA1 before being sent.
    fn psk_variant(psk: &str, ssid: &str) -> Variant<Box<dyn RefArg + 'static>> {
        match Self::decode_psk_hex(psk) {
            Some(key) => Variant(Box::new(key) as Box<dyn RefArg + 'static>),
            None => {
                let derived_psk = Self::derive_psk(psk, ssid);
                Variant(Box::new(derived_psk) as Box<dyn RefArg + 'static>)
            }
        }
    }

    /// Decodes a pre-shared key given as 64 hexadecimal digits.
    fn decode_psk_hex(psk: &str) -> Option<Vec<u8>> {
        if psk.len() != 64 || !psk.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        (0..psk.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&psk[i..i + 2], 16).ok())
            .collect()
    }

    async fn add_network(
        &self,
        interface_path: &OwnedObjectPath,
        config: &Config,
    ) -> Result<OwnedObjectPath> {
        debug!("adding network: {}", config.ssid);
        let mut network_config: HashMap<String, Variant<Box<dyn RefArg + 'static>>> =
            HashMap::new();
        network_config.insert(
            "ssid".to_string(),
            Variant(Box::new(config.ssid.clone()) as Box<dyn RefArg + 'static>),
        );

        match config.key_mgmt {
            KeyMgmt::Wpapsk => {
                // Set key_mgmt explicitly: wpa_supplicant's default also permits WPA-EAP.
                network_config.insert(
                    "key_mgmt".to_string(),
                    Variant(Box::new(String::from("WPA-PSK")) as Box<dyn RefArg + 'static>),
                );
                if !config.psk.is_empty() {
                    network_config.insert(
                        "psk".to_string(),
                        Self::psk_variant(&config.psk, &config.ssid),
                    );
                }
            }
            KeyMgmt::None => {
                network_config.insert(
                    "key_mgmt".to_string(),
                    Variant(Box::new(String::from("NONE")) as Box<dyn RefArg + 'static>),
                );
            }
        }

        // Our API does not mark hidden networks, so always scan for the SSID; this
        // is harmless for networks that do broadcast it.
        network_config.insert(
            "scan_ssid".to_string(),
            Variant(Box::new(1u32) as Box<dyn RefArg + 'static>),
        );

        debug!("calling dbus AddNetwork");
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            interface_path.clone(),
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );
        let (network_path,): (OwnedObjectPath,) = proxy
            .method_call(WPA_SUPPLICANT_INTERFACE, "AddNetwork", (network_config,))
            .await
            .context("Failed to add network")?;

        debug!("network added: {}", network_path);
        Ok(network_path)
    }

    async fn select_network_without_reassociate(
        &self,
        interface_path: &OwnedObjectPath,
        network_path: &OwnedObjectPath,
    ) -> Result<()> {
        debug!("calling dbus SelectNetwork");
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            interface_path.clone(),
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );
        proxy
            .method_call::<(), _, _, _>(
                WPA_SUPPLICANT_INTERFACE,
                "SelectNetwork",
                (network_path.clone(),),
            )
            .await
            .context("Failed to select network")?;

        debug!("network selected: {}", network_path);
        Ok(())
    }

    async fn disconnect(&self, interface_path: &OwnedObjectPath) -> Result<()> {
        debug!("calling dbus Disconnect");
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            interface_path.clone(),
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );
        proxy
            .method_call::<(), _, _, _>(WPA_SUPPLICANT_INTERFACE, "Disconnect", ())
            .await
            .context("Failed to disconnect")?;
        debug!("disconnected");
        Ok(())
    }

    async fn remove_network(
        &self,
        interface_path: &OwnedObjectPath,
        network_path: &OwnedObjectPath,
    ) -> Result<()> {
        debug!("calling dbus RemoveNetwork: {}", network_path);
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            interface_path.clone(),
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );
        proxy
            .method_call::<(), _, _, _>(
                WPA_SUPPLICANT_INTERFACE,
                "RemoveNetwork",
                (network_path.clone(),),
            )
            .await
            .context("Failed to remove network")?;
        debug!("network removed: {}", network_path);
        Ok(())
    }

    async fn save_config(&self, interface_path: &OwnedObjectPath) -> Result<()> {
        debug!("saving config");
        let proxy: Proxy<'_, Arc<SyncConnection>> = Proxy::new(
            WPA_SUPPLICANT_DEST,
            interface_path.clone(),
            Duration::from_secs(10),
            self.dbus_connection.clone(),
        );

        if let Err(e) = proxy
            .set(
                WPA_SUPPLICANT_INTERFACE,
                "UpdateConfig",
                Variant(Box::new("1".to_string()) as Box<dyn RefArg + 'static>),
            )
            .await
        {
            info!(
                "set UpdateConfig failed (may not be supported) continuing: {}",
                e
            );
        }

        if let Err(e) = proxy
            .method_call::<(), _, _, _>(WPA_SUPPLICANT_INTERFACE, "SaveConfig", ())
            .await
        {
            debug!("SaveConfig failed (may not be supported): {}", e);
        }

        debug!("config save attempted");
        Ok(())
    }

    async fn get_interface_state(&self, interface_path: &OwnedObjectPath) -> Result<String> {
        self.get_dbus_property(interface_path.as_ref(), WPA_SUPPLICANT_INTERFACE, "State")
            .await
    }

    async fn wait_for_connection(
        &self,
        interface_path: &OwnedObjectPath,
        timeout: Duration,
    ) -> Result<()> {
        use tokio::time::{interval_at, sleep, Instant};

        debug!("waiting for connection (timeout: {}s)", timeout.as_secs());
        let deadline = Instant::now() + timeout;
        let start = Instant::now();
        let mut check_interval = interval_at(
            start + Duration::from_millis(500),
            Duration::from_millis(500),
        );

        let mut last_state = String::new();

        loop {
            if Instant::now() > deadline {
                bail!(
                    "connection timeout after {:?}, last state: {}",
                    timeout,
                    last_state
                );
            }

            check_interval.tick().await;

            match self.get_interface_state(interface_path).await {
                Ok(state) => {
                    if state != last_state {
                        debug!(
                            "state: {} -> {} ({}s)",
                            last_state,
                            state,
                            start.elapsed().as_secs()
                        );
                        last_state = state.clone();
                    }

                    match state.as_str() {
                        "completed" => {
                            debug!("connection completed after {:?}", start.elapsed());
                            return Ok(());
                        }
                        "disconnected" | "inactive" => {
                            if start.elapsed() > STUCK_TIMEOUT {
                                bail!("network remained in '{}' state too long", state);
                            }
                        }
                        "interface_disabled" | "disabled" => {
                            bail!("interface is disabled");
                        }
                        "associating" | "associated" | "4way_handshake" | "group_handshake" => {
                            // connection in progress
                        }
                        _ => {
                            debug!("unknown state: {}", state);
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to get state: {}", e);
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(ssid: &str, security: Security, signal: f32) -> Network {
        Network {
            ssid: ssid.to_string(),
            security,
            signal,
        }
    }

    #[test]
    fn test_dedup_and_sort_networks() {
        let input = vec![
            network("The W-LAN", Security::Wpapsk, -48.0),
            network("yet another W-LAN", Security::Unsupported, -36.0),
            network("The W-LAN", Security::Wpapsk, -35.0),
            network("The W-LAN", Security::None, -37.0),
            network("another W-LAN", Security::Wpapsk, -30.0),
            network("", Security::None, -23.0),
        ];

        let expected = vec![
            network("", Security::None, -23.0),
            network("another W-LAN", Security::Wpapsk, -30.0),
            network("The W-LAN", Security::Wpapsk, -35.0),
            network("yet another W-LAN", Security::Unsupported, -36.0),
            network("The W-LAN", Security::None, -37.0),
        ];

        assert_eq!(expected, dedup_and_sort_networks(input));
    }

    #[test]
    fn test_dedup_keeps_strongest_signal_per_ssid_and_security() {
        let input = vec![
            network("dual-band", Security::Wpapsk, -70.0),
            network("dual-band", Security::Wpapsk, -42.0),
            network("dual-band", Security::Wpapsk, -55.0),
        ];

        assert_eq!(
            vec![network("dual-band", Security::Wpapsk, -42.0)],
            dedup_and_sort_networks(input)
        );
    }

    #[test]
    fn test_dedup_keeps_same_ssid_with_different_security() {
        // An access point may broadcast the same SSID open and encrypted. These are
        // two different networks for the user and must both be reported.
        let input = vec![
            network("guest", Security::None, -60.0),
            network("guest", Security::Wpapsk, -50.0),
        ];

        assert_eq!(
            vec![
                network("guest", Security::Wpapsk, -50.0),
                network("guest", Security::None, -60.0),
            ],
            dedup_and_sort_networks(input)
        );
    }

    #[test]
    fn test_sort_is_deterministic_for_equal_signal() {
        let input = vec![
            network("zeta", Security::None, -40.0),
            network("alpha", Security::None, -40.0),
            network("mike", Security::None, -40.0),
        ];

        let sorted = dedup_and_sort_networks(input);
        let ssids: Vec<&str> = sorted.iter().map(|n| n.ssid.as_str()).collect();
        assert_eq!(vec!["alpha", "mike", "zeta"], ssids);
    }

    #[test]
    fn test_connection_failed_is_recognizable_through_anyhow() {
        // `set_wifi_settings` tells a failed association from an internal error by
        // downcasting, so the error must survive the conversion to `anyhow::Error`.
        let err: anyhow::Error = ConnectionFailed {
            state: "disconnected".to_string(),
        }
        .into();

        let failure = err
            .downcast_ref::<ConnectionFailed>()
            .expect("ConnectionFailed must be recoverable");
        assert_eq!("disconnected", failure.state);

        let other = anyhow::anyhow!("some D-Bus failure");
        assert!(other.downcast_ref::<ConnectionFailed>().is_none());
    }

    #[test]
    fn test_system_bus_invalidates_current_generation() {
        let mut bus = SystemBus {
            generation: 7,
            connection: None,
        };

        assert!(bus.invalidate(7));
        assert!(bus.connection.is_none());
    }

    #[test]
    fn test_system_bus_keeps_newer_generation() {
        // The connection died and was re-established before the watching task got
        // to run. It must not drop the connection its successor installed.
        let mut bus = SystemBus {
            generation: 8,
            connection: None,
        };

        assert!(!bus.invalidate(7));
        assert_eq!(8, bus.generation);
    }

    #[test]
    fn test_decode_psk_hex_accepts_64_hex_digits() {
        let key = WpaDbusHelper::decode_psk_hex(&"a1B2".repeat(16)).expect("must decode");

        assert_eq!(32, key.len());
        assert_eq!(&[0xa1, 0xb2, 0xa1, 0xb2], &key[..4]);
    }

    #[test]
    fn test_scan_timeout_from_interval() {
        assert_eq!(Duration::from_secs(6), scan_timeout_from_interval(5));
        assert_eq!(Duration::from_secs(2), scan_timeout_from_interval(1));
    }

    #[test]
    fn test_scan_timeout_from_interval_is_clamped() {
        // A negative interval used to be cast to u64 directly, which produced a
        // duration of several hundred billion years.
        assert_eq!(Duration::from_secs(2), scan_timeout_from_interval(-1));
        assert_eq!(Duration::from_secs(2), scan_timeout_from_interval(i32::MIN));

        let max = Duration::from_secs(MAX_SCAN_INTERVAL as u64 + 1);
        assert_eq!(max, scan_timeout_from_interval(i32::MAX));
        assert_eq!(max, scan_timeout_from_interval(MAX_SCAN_INTERVAL + 1));
    }

    #[test]
    fn test_decode_psk_hex_rejects_passphrases() {
        // A passphrase of any other length, and a 64 character passphrase that is
        // not hexadecimal, have to be passed on as a string.
        assert!(WpaDbusHelper::decode_psk_hex("supersecret").is_none());
        assert!(WpaDbusHelper::decode_psk_hex(&"Z".repeat(64)).is_none());
        assert!(WpaDbusHelper::decode_psk_hex(&"a".repeat(63)).is_none());
        assert!(WpaDbusHelper::decode_psk_hex("").is_none());
    }

    #[test]
    fn test_psk_variant_signature() {
        // Both hex keys and passphrases are sent on the bus as raw bytes (byte array).
        // Hex keys are decoded directly, and passphrases are derived to PSK bytes via PBKDF2.
        let ssid = "TestNetwork";
        assert_eq!(
            "ay",
            WpaDbusHelper::psk_variant(&"ab".repeat(32), ssid)
                .0
                .signature()
                .to_string()
        );
        assert_eq!(
            "ay",
            WpaDbusHelper::psk_variant("supersecret", ssid)
                .0
                .signature()
                .to_string()
        );
    }

    fn variant<T: RefArg + 'static>(value: T) -> Variant<Box<dyn RefArg + 'static>> {
        Variant(Box::new(value) as Box<dyn RefArg + 'static>)
    }

    fn prop_map(entries: Vec<(&str, Variant<Box<dyn RefArg + 'static>>)>) -> PropMap {
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect()
    }

    fn key_mgmt(values: Vec<&str>) -> Variant<Box<dyn RefArg + 'static>> {
        let values: Vec<String> = values.into_iter().map(String::from).collect();
        variant(prop_map(vec![("KeyMgmt", variant(values))]))
    }

    #[test]
    fn test_convert_wpas_ssid_hex() {
        assert_eq!(
            "MyNet",
            WpaDbusHelper::convert_wpas_ssid_hex("4d794e6574").unwrap()
        );
    }

    #[test]
    fn test_convert_wpas_ssid_hex_rejects_invalid_input() {
        // Odd length, not hexadecimal, and valid hex that is not UTF-8.
        assert!(WpaDbusHelper::convert_wpas_ssid_hex("4d794e657").is_err());
        assert!(WpaDbusHelper::convert_wpas_ssid_hex("zzzz").is_err());
        assert!(WpaDbusHelper::convert_wpas_ssid_hex("ff").is_err());
    }

    #[test]
    fn test_extract_security_without_wpa_or_rsn() {
        assert_eq!(
            Security::None,
            WpaDbusHelper::extract_security(&prop_map(vec![]))
        );
    }

    #[test]
    fn test_extract_security_detects_wpa_psk() {
        let rsn = prop_map(vec![("RSN", key_mgmt(vec!["wpa-psk"]))]);
        assert_eq!(Security::Wpapsk, WpaDbusHelper::extract_security(&rsn));

        let wpa = prop_map(vec![("WPA", key_mgmt(vec!["wpa-psk"]))]);
        assert_eq!(Security::Wpapsk, WpaDbusHelper::extract_security(&wpa));
    }

    #[test]
    fn test_extract_security_reports_anything_else_as_unsupported() {
        let eap = prop_map(vec![("RSN", key_mgmt(vec!["wpa-eap"]))]);
        assert_eq!(Security::Unsupported, WpaDbusHelper::extract_security(&eap));

        // Present but without any key management listed.
        let empty = prop_map(vec![("WPA", key_mgmt(vec![]))]);
        assert_eq!(
            Security::Unsupported,
            WpaDbusHelper::extract_security(&empty)
        );
    }

    #[test]
    fn test_convert_bss_to_ssid() {
        let bss = prop_map(vec![
            ("SSID", variant(b"MyNet".to_vec())),
            ("Signal", variant(-42i16)),
            ("RSN", key_mgmt(vec!["wpa-psk"])),
        ]);

        assert_eq!(
            Some(network("MyNet", Security::Wpapsk, -42.0)),
            WpaDbusHelper::convert_bss_to_ssid(&bss)
        );
    }

    #[test]
    fn test_convert_bss_to_ssid_skips_hidden_networks() {
        // A hidden network is announced with an empty SSID and cannot be joined
        // by name, so it is not offered to the client.
        let bss = prop_map(vec![
            ("SSID", variant(Vec::<u8>::new())),
            ("Signal", variant(-42i16)),
        ]);

        assert!(WpaDbusHelper::convert_bss_to_ssid(&bss).is_none());
    }

    #[test]
    fn test_derive_psk_from_passphrase() {
        let passphrase = "TestPassword123";
        let ssid = "TestNetwork";
        let derived = WpaDbusHelper::derive_psk(passphrase, ssid);

        // Verify output is 32 bytes (256 bits)
        assert_eq!(derived.len(), 32);

        // Verify it's deterministic
        let derived2 = WpaDbusHelper::derive_psk(passphrase, ssid);
        assert_eq!(derived, derived2);

        let derived_different = WpaDbusHelper::derive_psk("DifferentPassword", ssid);
        assert_ne!(derived, derived_different);

        let derived_different_ssid = WpaDbusHelper::derive_psk(passphrase, "DifferentNetwork");
        assert_ne!(derived, derived_different_ssid);
    }

    #[test]
    fn test_psk_variant_with_64_char_hex_psk() {
        // 64-character hex PSK should be decoded as-is, not derived
        let psk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let ssid = "TestNetwork";

        let variant = WpaDbusHelper::psk_variant(psk_hex, ssid);

        // The variant should contain the raw bytes decoded from the hex string
        let key = cast::<Vec<u8>>(&*variant.0).expect("variant should hold a Vec<u8>");
        let expected = Vec::<u8>::from(&[
            1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103,
            137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239,
        ]);
        assert_eq!(key, &expected);
    }

    #[test]
    fn test_psk_variant_with_passphrase() {
        // 8-63 character passphrase should be derived using PBKDF2
        let passphrase = "MyPassword123";
        let ssid = "TestNetwork";

        let variant = WpaDbusHelper::psk_variant(passphrase, ssid);

        // The variant should contain the PSK derived from the passphrase via PBKDF2
        let key = cast::<Vec<u8>>(&*variant.0).expect("variant should hold a Vec<u8>");
        let expected = Vec::<u8>::from(&[
            13, 6, 239, 117, 250, 179, 51, 225, 81, 159, 183, 159, 88, 18, 209, 23, 105, 200, 15,
            84, 26, 26, 143, 247, 187, 57, 100, 155, 14, 38, 232, 130,
        ]);
        assert_eq!(key, &expected);
    }

    #[test]
    fn test_decode_psk_hex_valid() {
        let psk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let decoded = WpaDbusHelper::decode_psk_hex(psk_hex);

        assert!(decoded.is_some());
        let bytes = decoded.unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x23);
    }

    #[test]
    fn test_decode_psk_hex_invalid_length() {
        let psk_short = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
        assert!(WpaDbusHelper::decode_psk_hex(psk_short).is_none());

        let psk_long = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00";
        assert!(WpaDbusHelper::decode_psk_hex(psk_long).is_none());
    }

    #[test]
    fn test_decode_psk_hex_invalid_characters() {
        // Contains non-hex character 'g'
        let psk_invalid = "0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(WpaDbusHelper::decode_psk_hex(psk_invalid).is_none());
    }
}
