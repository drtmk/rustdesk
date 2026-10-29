mod artifact;
mod download;

use crate::common::do_check_software_update;
use artifact::verified_update_artifact_from_release_page_url;
pub(crate) use artifact::{current_update_arch, current_update_format, current_update_platform};
pub use artifact::{
    current_update_artifact_query, get_update_download_file_from_url,
    verified_update_artifact_for_download_url, verified_update_artifact_for_release_page_url,
};
use base::config::keys;
use download::ensure_verified_update_artifact;
pub(crate) use download::remove_update_file;
use hbb_common::{bail, config, log, ResultType};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    time::{Duration, Instant},
};

#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "macos")]
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

#[cfg(target_os = "macos")]
struct MacUpdateLock {
    _file: std::fs::File,
}

#[cfg(target_os = "macos")]
fn acquire_mac_update_lock() -> ResultType<MacUpdateLock> {
    let path = std::path::PathBuf::from("/var/run/rustdesk-update.lock");
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(hbb_common::libc::O_NOFOLLOW | hbb_common::libc::O_CLOEXEC)
        .open(&path)?;
    let metadata = handle.metadata()?;
    if !metadata.file_type().is_file() || metadata.uid() != 0 {
        bail!("[root-update] update lock is not a root-owned regular file");
    }
    handle.set_permissions(std::fs::Permissions::from_mode(0o600))?;

    // Keep the descriptor open through update preparation and detached-script
    // launch. O_CLOEXEC means this lock does not cover the detached bundle
    // swap; flock is released when this guard is dropped or the process exits.
    let lock_result = unsafe {
        hbb_common::libc::flock(
            handle.as_raw_fd(),
            hbb_common::libc::LOCK_EX | hbb_common::libc::LOCK_NB,
        )
    };
    if lock_result != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            bail!("[root-update] another update is already running");
        }
        return Err(err.into());
    }
    Ok(MacUpdateLock { _file: handle })
}

enum UpdateMsg {
    CheckUpdate,
    Exit,
}

lazy_static::lazy_static! {
    static ref TX_MSG : Mutex<Sender<UpdateMsg>> = Mutex::new(start_auto_update_check());
}

static CONTROLLING_SESSION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Initial wait after startup before the first update check (30 seconds).
pub const INITIAL_CHECK_DELAY: Duration = Duration::from_secs(30);

/// One full day — default interval between update checks.
pub const DUR_ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);

/// Minimum interval between consecutive update checks (10 minutes).
pub const MIN_INTERVAL: Duration = Duration::from_secs(60 * 10);

/// Retry interval when an update check fails or a session is active (30 minutes).
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 30);

pub fn update_controlling_session_count(count: usize) {
    CONTROLLING_SESSION_COUNT.store(count, Ordering::SeqCst);
}

#[allow(dead_code)]
pub fn start_auto_update() {
    let _sender = TX_MSG.lock().unwrap();
}

#[allow(dead_code)]
pub fn manually_check_update() -> ResultType<()> {
    let sender = TX_MSG.lock().unwrap();
    sender.send(UpdateMsg::CheckUpdate)?;
    Ok(())
}

#[allow(dead_code)]
pub fn stop_auto_update() {
    let sender = TX_MSG.lock().unwrap();
    sender.send(UpdateMsg::Exit).unwrap_or_default();
}

#[inline]
/// Returns true when there are no active incoming or outgoing connections.
/// Used to avoid updating while a remote session is in progress.
pub fn has_no_active_conns() -> bool {
    let conns = crate::Connection::alive_conns();
    conns.is_empty() && has_no_controlling_conns()
}

#[cfg(any(not(target_os = "windows"), feature = "flutter"))]
fn has_no_controlling_conns() -> bool {
    CONTROLLING_SESSION_COUNT.load(Ordering::SeqCst) == 0
}

#[cfg(not(any(not(target_os = "windows"), feature = "flutter")))]
fn has_no_controlling_conns() -> bool {
    let app_exe = format!("{}.exe", crate::get_app_name().to_lowercase());
    for arg in [
        "--connect",
        "--play",
        "--file-transfer",
        "--view-camera",
        "--port-forward",
        "--rdp",
    ] {
        if !crate::platform::get_pids_of_process_with_first_arg(&app_exe, arg).is_empty() {
            return false;
        }
    }
    true
}

fn start_auto_update_check() -> Sender<UpdateMsg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || start_auto_update_check_(rx));
    return tx;
}

fn start_auto_update_check_(rx_msg: Receiver<UpdateMsg>) {
    std::thread::sleep(INITIAL_CHECK_DELAY);
    if let Err(e) = check_update(false) {
        log::error!("Error checking for updates: {}", e);
    }

    let mut last_check_time = Instant::now();
    let mut check_interval = DUR_ONE_DAY;
    loop {
        let recv_res = rx_msg.recv_timeout(check_interval);
        match &recv_res {
            Ok(UpdateMsg::CheckUpdate) | Err(_) => {
                if last_check_time.elapsed() < MIN_INTERVAL {
                    // log::debug!("Update check skipped due to minimum interval.");
                    continue;
                }
                // Don't check update if there are alive connections.
                if !has_no_active_conns() {
                    check_interval = RETRY_INTERVAL;
                    continue;
                }
                if let Err(e) = check_update(matches!(recv_res, Ok(UpdateMsg::CheckUpdate))) {
                    log::error!("Error checking for updates: {}", e);
                    check_interval = RETRY_INTERVAL;
                } else {
                    last_check_time = Instant::now();
                    check_interval = DUR_ONE_DAY;
                }
            }
            Ok(UpdateMsg::Exit) => break,
        }
    }
}

fn check_update(_manually: bool) -> ResultType<()> {
    return Ok(());
}

#[cfg(target_os = "windows")]
fn verified_update_path(
    p: &str,
    expected_sha256: &str,
    kind: &str,
    file_path: &Path,
) -> Option<(crate::platform::VerifiedUpdateFile, String)> {
    let update_file = match crate::platform::copy_and_verify_update_file_sha256(p, expected_sha256)
    {
        Ok(update_file) => update_file,
        Err(e) => {
            log::error!("Refusing to update from invalid {}: {}", kind, e);
            remove_update_file(file_path);
            return None;
        }
    };
    let update_path = match update_file.path_str() {
        Ok(path) => path.to_owned(),
        Err(e) => {
            log::error!("Failed to get verified {} path: {}", kind, e);
            update_file.cleanup();
            remove_update_file(file_path);
            return None;
        }
    };
    Some((update_file, update_path))
}

#[cfg(target_os = "windows")]
fn update_new_version(update_msi: bool, version: &str, file_path: &PathBuf, expected_sha256: &str) {
    log::debug!(
        "New version is downloaded, update begin, update msi: {update_msi}, version: {version}, file: {:?}",
        file_path.to_str()
    );
    if let Some(p) = file_path.to_str() {
        if let Some(session_id) = crate::platform::get_current_process_session_id() {
            if update_msi {
                let Some((update_file, update_path)) =
                    verified_update_path(p, expected_sha256, "msi", file_path)
                else {
                    return;
                };
                let result = crate::platform::update_me_msi(&update_path, expected_sha256, true);
                update_file.cleanup();
                match result {
                    Ok(_) => {
                        log::debug!("New version \"{}\" updated.", version);
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to install the new msi version  \"{}\": {}",
                            version,
                            e
                        );
                        remove_update_file(file_path);
                    }
                }
            } else {
                let Some((update_file, update_path)) =
                    verified_update_path(p, expected_sha256, "exe", file_path)
                else {
                    return;
                };
                let custom_client_staging_dir = if crate::is_custom_client() {
                    let custom_client_staging_dir =
                        crate::platform::get_custom_client_staging_dir();
                    if let Err(e) = crate::platform::handle_custom_client_staging_dir_before_update(
                        &custom_client_staging_dir,
                    ) {
                        log::error!(
                            "Failed to handle custom client staging dir before update: {}",
                            e
                        );
                        update_file.cleanup();
                        remove_update_file(file_path);
                        return;
                    }
                    Some(custom_client_staging_dir)
                } else {
                    // Clean up any residual staging directory from previous custom client
                    let staging_dir = crate::platform::get_custom_client_staging_dir();
                    hbb_common::allow_err!(crate::platform::remove_custom_client_staging_dir(
                        &staging_dir
                    ));
                    None
                };
                let update_launched = match crate::platform::launch_privileged_process(
                    session_id,
                    &format!("\"{}\" --update", update_path),
                ) {
                    Ok(h) => {
                        if h.is_null() {
                            log::error!("Failed to update to the new version: {}", version);
                            false
                        } else {
                            log::debug!("New version \"{}\" is launched.", version);
                            unsafe {
                                winapi::um::handleapi::CloseHandle(h);
                            }
                            true
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to run the new version: {}", e);
                        false
                    }
                };
                if !update_launched {
                    if let Some(dir) = custom_client_staging_dir {
                        hbb_common::allow_err!(crate::platform::remove_custom_client_staging_dir(
                            &dir
                        ));
                    }
                    update_file.cleanup();
                    remove_update_file(file_path);
                }
            }
        } else {
            log::error!(
                "Failed to get the current process session id, Error {}",
                std::io::Error::last_os_error()
            );
            remove_update_file(file_path);
        }
    } else {
        // unreachable!()
        log::error!(
            "Failed to convert the file path to string: {}",
            file_path.display()
        );
    }
}

/// Queries all active connections (remote, file-transfer, port-forward, camera, terminal)
/// from every logged-in user's --server process via IPC.
/// The root service cannot read connection state directly since connections
/// live in user --server processes. Handles fast user switching by querying
/// all GUI users, including the login-window server at UID 0. Falls back to
/// false (assumes sessions active) on any IPC error to avoid updating during
/// an unknown session state.
#[cfg(target_os = "macos")]
pub fn has_no_active_conns_ipc() -> bool {
    let result = match hbb_common::tokio::runtime::Runtime::new() {
        Ok(rt) => rt.block_on(query_no_active_conns_ipc()),
        Err(err) => Err(hbb_common::anyhow::anyhow!(
            "failed to create IPC runtime: {err}"
        )),
    };
    match result {
        Ok(no_active_conns) => no_active_conns,
        Err(err) => {
            log::warn!(
                "[root-update] Unable to determine active connection state; deferring update: {}",
                err
            );
            false
        }
    }
}

#[cfg(target_os = "macos")]
async fn query_no_active_conns_ipc() -> ResultType<bool> {
    const IPC_TIMEOUT_MS: u64 = 1_000;
    // An empty GUI user set maps to UID 0 so LoginWindow must also confirm it is idle.
    let uids = crate::platform::get_logged_in_uids();
    for uid in uids {
        let mut conn = crate::ipc::connect_for_uid(IPC_TIMEOUT_MS, uid, "")
            .await
            .map_err(|err| {
                hbb_common::anyhow::anyhow!("IPC connection failed for uid {uid}: {err}")
            })?;
        conn.send(&crate::ipc::Data::HasNoActiveConns(None))
            .await
            .map_err(|err| hbb_common::anyhow::anyhow!("IPC send failed for uid {uid}: {err}"))?;
        match conn.next_timeout(IPC_TIMEOUT_MS).await {
            Ok(Some(crate::ipc::Data::HasNoActiveConns(Some(true)))) => {}
            Ok(Some(crate::ipc::Data::HasNoActiveConns(Some(false)))) => return Ok(false),
            Ok(Some(_)) => bail!("unexpected active-connection IPC response for uid {uid}"),
            Ok(None) => bail!("active-connection IPC closed for uid {uid}"),
            Err(err) => bail!("active-connection IPC failed for uid {uid}: {err}"),
        }
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn wait_for_failed_update_retry() {
    const FAILURE_MARKER: &str = "/var/root/.rustdeskupdate_failed";
    let marker = std::path::Path::new(FAILURE_MARKER);
    if !marker.exists() {
        return;
    }

    // The updater script records failure immediately before launchd restarts
    // the old daemon. Preserve the retry deadline across that restart instead
    // of consuming the marker and retrying the same broken release in 30 sec.
    let remaining = std::fs::metadata(marker)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| {
            std::time::SystemTime::now()
                .duration_since(modified)
                .ok()
        })
        .map(|elapsed| RETRY_INTERVAL.saturating_sub(elapsed))
        .unwrap_or(RETRY_INTERVAL);
    if !remaining.is_zero() {
        log::info!(
            "[root-update] Previous update failed; retrying in {} seconds.",
            remaining.as_secs()
        );
        std::thread::sleep(remaining);
    }
    match std::fs::remove_file(marker) {
        Ok(()) => log::info!("[root-update] Previous update retry interval elapsed."),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => log::warn!("[root-update] Failed to clear failure marker: {}", err),
    }
}

/// Starts the background silent auto-update scheduler for macOS.
/// Called from `start_os_service()` which runs as root via LaunchDaemon.
#[cfg(target_os = "macos")]
pub fn start_auto_update_macos() {
    let spawn_result = std::thread::Builder::new()
        .name("rustdesk-auto-update".to_owned())
        .spawn(|| {
            log::info!("[root-update] Auto-update scheduler thread started.");
            std::thread::sleep(INITIAL_CHECK_DELAY);
            wait_for_failed_update_retry();
            let mut interval = DUR_ONE_DAY;
            loop {
                log::info!("[root-update] Running scheduled update check...");
                let no_active_conns = has_no_active_conns_ipc();
                if !no_active_conns {
                    log::info!("[root-update] Active session in progress, retrying in 10 min.");
                    interval = MIN_INTERVAL;
                } else {
                    match check_update_as_root() {
                        Ok(update_started) => {
                            if update_started {
                                // The replacement script is detached and may fail
                                // after this process returns. Always retry at the
                                // failure interval until the new daemon replaces us.
                                interval = RETRY_INTERVAL;
                            } else {
                                interval = DUR_ONE_DAY;
                            }
                        }
                        Err(e) => {
                            log::error!("[root-update] Update check failed: {}", e);
                            interval = RETRY_INTERVAL;
                        }
                    }
                }
                std::thread::sleep(interval);
            }
        });
    if let Err(err) = spawn_result {
        log::error!("[root-update] Failed to start scheduler thread: {}", err);
    }
}

#[cfg(target_os = "macos")]
pub fn check_update_as_root() -> ResultType<bool> {
    return Ok(false);
}
