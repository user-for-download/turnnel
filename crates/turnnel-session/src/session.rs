use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use turnnel_stun::attribute::Attribute;
use turnnel_stun::channel_data::ChannelData;
use turnnel_stun::integrity::long_term_key;
use turnnel_stun::message::StunMessage;
use turnnel_stun::types::{Class, Method};
use turnnel_stun::{demux, PacketType};

use crate::transport::{TransportProtocol, TransportRx, TransportTx};

const MAX_PENDING_DATA: usize = 1024;

#[derive(Clone)]
pub struct TurnCredentials {
    pub server_addr: SocketAddr,
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
}

// Issue 1: mask password in Debug output to prevent accidental leakage in logs
impl std::fmt::Debug for TurnCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnCredentials")
            .field("server_addr", &self.server_addr)
            .field("username", &self.username)
            .field("password", &"********")
            .field("realm", &self.realm)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub credentials: TurnCredentials,
    pub protocol: TransportProtocol,
    pub peer_addr: SocketAddr,
    pub channel_number: u16,
    pub stun_timeout: Duration,
    pub requested_lifetime: u32,
    pub max_reconnect_attempts: u32,
    pub reconnect_delay: Duration,
}

impl SessionConfig {
    pub fn new(
        credentials: TurnCredentials,
        protocol: TransportProtocol,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            credentials,
            protocol,
            peer_addr,
            channel_number: 0x4000,
            stun_timeout: Duration::from_secs(5),
            requested_lifetime: 600,
            max_reconnect_attempts: 3,
            reconnect_delay: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Init,
    Allocated,
    Permitted,
    Active,
    Failed,
}

#[derive(Debug, Clone)]
pub struct AllocationInfo {
    pub relay_addr: SocketAddr,
    pub mapped_addr: Option<SocketAddr>,
    pub lifetime: u32,
    pub allocated_at: Instant,
}

#[derive(Debug)]
pub enum TurnEvent {
    Data(Bytes),
    StunResponse(StunMessage),
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("TURN error {code}: {reason}")]
    TurnError { code: u16, reason: String },

    #[error("timeout waiting for STUN response")]
    Timeout,

    #[error("unexpected STUN response: expected {expected:?}, got {got:?}")]
    UnexpectedResponse { expected: Method, got: Method },

    #[error("no relay address in Allocate response")]
    NoRelayAddress,

    #[error("MESSAGE-INTEGRITY verification failed")]
    IntegrityFailed,

    #[error("session not in required state {required:?}, currently {current:?}")]
    WrongState {
        required: SessionState,
        current: SessionState,
    },

    #[error("transport disconnected")]
    Disconnected,

    #[error("reconnection failed after {attempts} attempts")]
    ReconnectFailed { attempts: u32 },

    #[error(transparent)]
    Transport(#[from] anyhow::Error),
}

pub struct TurnSession {
    tx: Box<dyn TransportTx>,
    rx: Box<dyn TransportRx>,
    config: SessionConfig,
    state: SessionState,

    hmac_key: Option<Vec<u8>>,
    server_realm: Option<String>,
    server_nonce: Option<String>,
    allocation: Option<AllocationInfo>,

    last_permission_refresh: Option<Instant>,
    last_channel_refresh: Option<Instant>,

    pending_data: VecDeque<Bytes>,
}

impl TurnSession {
    pub async fn new(config: SessionConfig) -> Result<Self, SessionError> {
        let (tx, rx) =
            crate::transport::connect(config.credentials.server_addr, &config.protocol).await?;

        Ok(Self {
            tx,
            rx,
            config,
            state: SessionState::Init,
            hmac_key: None,
            server_realm: None,
            server_nonce: None,
            allocation: None,
            last_permission_refresh: None,
            last_channel_refresh: None,
            pending_data: VecDeque::new(),
        })
    }

    pub async fn establish(&mut self) -> Result<(), SessionError> {
        self.allocate().await?;
        self.create_permission().await?;
        self.channel_bind().await?;

        tracing::info!(
            relay = %self.allocation.as_ref().unwrap().relay_addr,
            peer = %self.config.peer_addr,
            channel = %format!("{:#06x}", self.config.channel_number),
            protocol = ?self.config.protocol,
            "TURN session active"
        );

        Ok(())
    }

    pub async fn deallocate(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Init || self.hmac_key.is_none() {
            return Ok(());
        }

        let mut req = StunMessage::new(Method::Refresh, Class::Request);
        req.add(Attribute::Lifetime(0));
        self.add_auth_attrs(&mut req);

        let key = self.hmac_key.as_ref().unwrap();
        let encoded = req.encode(Some(key), false);
        self.tx.send(encoded.freeze()).await?;

        match self
            .recv_stun_response(Method::Refresh, &req.transaction_id)
            .await
        {
            Ok(resp) => {
                if resp.class == Class::SuccessResponse {
                    tracing::info!("TURN allocation released");
                } else {
                    let (code, reason) = resp.get_error_code().unwrap_or((0, "unknown"));
                    tracing::warn!(code, reason, "deallocate got error response");
                }
            }
            Err(SessionError::Timeout) => {
                tracing::debug!("deallocate response timed out (allocation will expire naturally)");
            }
            Err(e) => {
                tracing::debug!("deallocate failed: {e}");
            }
        }

        self.state = SessionState::Init;
        self.allocation = None;
        Ok(())
    }

    async fn allocate(&mut self) -> Result<(), SessionError> {
        let mut req = StunMessage::new(Method::Allocate, Class::Request);

        req.add(Attribute::RequestedTransport(17));
        req.add(Attribute::Lifetime(self.config.requested_lifetime));

        let encoded = req.encode(None, false);
        self.tx.send(encoded.freeze()).await?;

        let resp = self
            .recv_stun_response(Method::Allocate, &req.transaction_id)
            .await?;

        if resp.class == Class::ErrorResponse {
            let (code, reason) = resp.get_error_code().unwrap_or((0, "unknown"));

            if code != 401 {
                return Err(SessionError::TurnError {
                    code,
                    reason: reason.to_string(),
                });
            }

            let realm = resp
                .get_realm()
                .ok_or_else(|| SessionError::TurnError {
                    code: 401,
                    reason: "no realm in 401".into(),
                })?
                .to_string();

            let nonce = resp
                .get_nonce()
                .ok_or_else(|| SessionError::TurnError {
                    code: 401,
                    reason: "no nonce in 401".into(),
                })?
                .to_string();

            self.server_realm = Some(realm.clone());
            self.server_nonce = Some(nonce.clone());

            let effective_realm = self.config.credentials.realm.as_deref().unwrap_or(&realm);
            self.hmac_key = Some(long_term_key(
                &self.config.credentials.username,
                effective_realm,
                &self.config.credentials.password,
            ));

            return self.allocate_authenticated(&realm, &nonce).await;
        }

        if resp.class == Class::SuccessResponse {
            return self.handle_allocate_success(&resp);
        }

        Err(SessionError::TurnError {
            code: 0,
            reason: "unexpected allocate response".into(),
        })
    }

    async fn allocate_authenticated(
        &mut self,
        realm: &str,
        nonce: &str,
    ) -> Result<(), SessionError> {
        let mut req = StunMessage::new(Method::Allocate, Class::Request);
        req.add(Attribute::RequestedTransport(17));
        req.add(Attribute::Lifetime(self.config.requested_lifetime));
        req.add(Attribute::Username(
            self.config.credentials.username.clone(),
        ));
        req.add(Attribute::Realm(realm.to_string()));
        req.add(Attribute::Nonce(nonce.to_string()));

        let key = self.hmac_key.as_ref().unwrap();
        let encoded = req.encode(Some(key), false);

        self.tx.send(encoded.freeze()).await?;

        let resp = self
            .recv_stun_response(Method::Allocate, &req.transaction_id)
            .await?;

        if resp.class == Class::ErrorResponse {
            let (code, reason) = resp.get_error_code().unwrap_or((0, "unknown"));
            return Err(SessionError::TurnError {
                code,
                reason: reason.to_string(),
            });
        }

        self.handle_allocate_success(&resp)
    }

    fn handle_allocate_success(&mut self, resp: &StunMessage) -> Result<(), SessionError> {
        // Issue 5: update nonce from any success response (RFC 5766 §7.3)
        if let Some(nonce) = resp.get_nonce() {
            self.server_nonce = Some(nonce.to_string());
        }

        let relay_addr = resp
            .get_xor_relayed_address()
            .ok_or(SessionError::NoRelayAddress)?;

        let mapped_addr = resp.get_xor_mapped_address();
        let lifetime = resp.get_lifetime().unwrap_or(600);

        self.allocation = Some(AllocationInfo {
            relay_addr,
            mapped_addr,
            lifetime,
            allocated_at: Instant::now(),
        });

        self.state = SessionState::Allocated;
        Ok(())
    }

    async fn create_permission(&mut self) -> Result<(), SessionError> {
        for attempt in 0..2u8 {
            let peer_ip = self.config.peer_addr.ip();
            let perm_addr = SocketAddr::new(peer_ip, 0);

            let mut req = StunMessage::new(Method::CreatePermission, Class::Request);
            req.add(Attribute::XorPeerAddress(perm_addr));
            self.add_auth_attrs(&mut req);

            let key = self.hmac_key.as_ref().unwrap();
            let encoded = req.encode(Some(key), false);
            self.tx.send(encoded.freeze()).await?;

            let resp = self
                .recv_stun_response(Method::CreatePermission, &req.transaction_id)
                .await?;

            if resp.class == Class::ErrorResponse {
                let (code, reason) = resp.get_error_code().unwrap_or((0, "unknown"));

                if code == 438 && attempt == 0 {
                    if let Some(new_nonce) = resp.get_nonce() {
                        tracing::debug!("stale nonce on CreatePermission, retrying");
                        self.server_nonce = Some(new_nonce.to_string());
                        continue;
                    }
                }

                if code == 403 {
                    return Err(SessionError::TurnError {
                        code,
                        reason: format!(
                            "{reason} — the TURN server refused to create a permission for peer IP {peer_ip}. \
                             This typically means the address is loopback/private/reserved. \
                             Use the PUBLIC IP of the peer machine.",
                        ),
                    });
                }

                return Err(SessionError::TurnError {
                    code,
                    reason: reason.to_string(),
                });
            }

            if self.state == SessionState::Allocated {
                self.state = SessionState::Permitted;
            }
            self.last_permission_refresh = Some(Instant::now());

            // Issue 5: update nonce from success response
            if let Some(nonce) = resp.get_nonce() {
                self.server_nonce = Some(nonce.to_string());
            }

            return Ok(());
        }

        Err(SessionError::TurnError {
            code: 438,
            reason: "stale nonce persisted on CreatePermission".into(),
        })
    }

    async fn channel_bind(&mut self) -> Result<(), SessionError> {
        for attempt in 0..2u8 {
            let mut req = StunMessage::new(Method::ChannelBind, Class::Request);
            req.add(Attribute::ChannelNumber(self.config.channel_number));
            req.add(Attribute::XorPeerAddress(self.config.peer_addr));
            self.add_auth_attrs(&mut req);

            let key = self.hmac_key.as_ref().unwrap();
            let encoded = req.encode(Some(key), false);
            self.tx.send(encoded.freeze()).await?;

            let resp = self
                .recv_stun_response(Method::ChannelBind, &req.transaction_id)
                .await?;

            if resp.class == Class::ErrorResponse {
                let (code, reason) = resp.get_error_code().unwrap_or((0, "unknown"));

                if code == 438 && attempt == 0 {
                    if let Some(new_nonce) = resp.get_nonce() {
                        tracing::debug!("stale nonce on ChannelBind, retrying");
                        self.server_nonce = Some(new_nonce.to_string());
                        continue;
                    }
                }

                return Err(SessionError::TurnError {
                    code,
                    reason: reason.to_string(),
                });
            }

            self.state = SessionState::Active;
            self.last_channel_refresh = Some(Instant::now());

            // Issue 5: update nonce from success response
            if let Some(nonce) = resp.get_nonce() {
                self.server_nonce = Some(nonce.to_string());
            }

            return Ok(());
        }

        Err(SessionError::TurnError {
            code: 438,
            reason: "stale nonce persisted on ChannelBind".into(),
        })
    }

    // Issue 4: &mut self is semantically correct for an I/O operation
    // and prevents the compiler from allowing concurrent sends that could
    // interleave channel data frames on TCP.
    pub async fn send_data(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        if self.state != SessionState::Active {
            return Err(SessionError::WrongState {
                required: SessionState::Active,
                current: self.state,
            });
        }

        let cd = ChannelData::new(self.config.channel_number, Bytes::copy_from_slice(payload))
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let pad = matches!(
            self.config.protocol,
            TransportProtocol::Tcp | TransportProtocol::Tls { .. }
        );
        let encoded = cd.encode(pad);

        self.tx.send(encoded.freeze()).await?;
        Ok(())
    }

    pub async fn recv_event(&mut self) -> Result<TurnEvent, SessionError> {
        // Drain any data buffered during a prior recv_stun_response call
        if let Some(data) = self.pending_data.pop_front() {
            return Ok(TurnEvent::Data(data));
        }

        loop {
            let (frame, _src) = self.recv_frame().await?;

            match demux(&frame) {
                PacketType::ChannelData => {
                    let cd = ChannelData::decode(&frame)
                        .map_err(|e| anyhow::anyhow!("ChannelData decode: {e}"))?;
                    return Ok(TurnEvent::Data(cd.data));
                }
                PacketType::Stun => {
                    let msg = StunMessage::decode(&frame)
                        .map_err(|e| anyhow::anyhow!("STUN decode: {e}"))?;
                    return Ok(TurnEvent::StunResponse(msg));
                }
                _ => continue,
            }
        }
    }

    pub async fn recv_data(&mut self) -> Result<Bytes, SessionError> {
        loop {
            match self.recv_event().await? {
                TurnEvent::Data(data) => return Ok(data),
                TurnEvent::StunResponse(_) => continue,
            }
        }
    }

    pub async fn refresh_allocation(&mut self) -> Result<(), SessionError> {
        for attempt in 0..2u8 {
            let mut req = StunMessage::new(Method::Refresh, Class::Request);
            req.add(Attribute::Lifetime(self.config.requested_lifetime));
            self.add_auth_attrs(&mut req);

            let key = self.hmac_key.as_ref().unwrap();
            let encoded = req.encode(Some(key), false);
            self.tx.send(encoded.freeze()).await?;

            let resp = self
                .recv_stun_response(Method::Refresh, &req.transaction_id)
                .await?;

            if resp.class == Class::ErrorResponse {
                let (code, reason) = resp.get_error_code().unwrap_or((0, "unknown"));

                if code == 438 && attempt == 0 {
                    if let Some(new_nonce) = resp.get_nonce() {
                        self.server_nonce = Some(new_nonce.to_string());
                        continue;
                    }
                }

                return Err(SessionError::TurnError {
                    code,
                    reason: reason.to_string(),
                });
            }

            if let Some(ref mut alloc) = self.allocation {
                alloc.lifetime = resp.get_lifetime().unwrap_or(alloc.lifetime);
                alloc.allocated_at = Instant::now();
            }

            // Issue 5: update nonce from success response
            if let Some(nonce) = resp.get_nonce() {
                self.server_nonce = Some(nonce.to_string());
            }

            return Ok(());
        }

        Err(SessionError::TurnError {
            code: 438,
            reason: "stale nonce persisted".into(),
        })
    }

    pub async fn refresh_permission(&mut self) -> Result<(), SessionError> {
        self.create_permission().await
    }

    pub async fn refresh_channel(&mut self) -> Result<(), SessionError> {
        let saved = self.state;
        let res = self.channel_bind().await;
        if res.is_err() {
            self.state = saved;
        }
        res
    }

    /// Attempt to reconnect the transport and re-establish the full TURN session.
    pub async fn reconnect(&mut self) -> Result<(), SessionError> {
        let max_attempts = self.config.max_reconnect_attempts;
        let delay = self.config.reconnect_delay;

        for attempt in 1..=max_attempts {
            tracing::warn!(attempt, max_attempts, "attempting reconnection");

            tokio::time::sleep(delay).await;

            match crate::transport::connect(
                self.config.credentials.server_addr,
                &self.config.protocol,
            )
            .await
            {
                Ok((tx, rx)) => {
                    self.tx = tx;
                    self.rx = rx;
                }
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "transport reconnect failed");
                    continue;
                }
            }

            self.state = SessionState::Init;
            self.server_nonce = None;
            self.allocation = None;
            self.last_permission_refresh = None;
            self.last_channel_refresh = None;
            self.pending_data.clear();

            match self.establish().await {
                Ok(()) => {
                    tracing::info!(attempt, "reconnection successful");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "re-establish failed");
                    continue;
                }
            }
        }

        self.state = SessionState::Failed;
        Err(SessionError::ReconnectFailed {
            attempts: max_attempts,
        })
    }

    fn add_auth_attrs(&self, msg: &mut StunMessage) {
        msg.add(Attribute::Username(
            self.config.credentials.username.clone(),
        ));
        if let Some(ref r) = self.server_realm {
            msg.add(Attribute::Realm(r.clone()));
        }
        if let Some(ref n) = self.server_nonce {
            msg.add(Attribute::Nonce(n.clone()));
        }
    }

    /// Low-level receive that detects disconnection for stream transports.
    async fn recv_frame(&mut self) -> Result<(Bytes, SocketAddr), SessionError> {
        match self.rx.recv().await {
            Ok(r) => Ok(r),
            Err(e) => {
                // Issue 8: use io::ErrorKind instead of string matching
                if is_disconnect_error(&e) {
                    Err(SessionError::Disconnected)
                } else {
                    Err(SessionError::Transport(e))
                }
            }
        }
    }

    /// Low-level receive with timeout. Returns None on timeout.
    async fn recv_frame_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<(Bytes, SocketAddr)>, SessionError> {
        match self.rx.recv_timeout(timeout).await {
            Ok(r) => Ok(r),
            Err(e) => {
                // Issue 8: use io::ErrorKind instead of string matching
                if is_disconnect_error(&e) {
                    Err(SessionError::Disconnected)
                } else {
                    Err(SessionError::Transport(e))
                }
            }
        }
    }

    async fn recv_stun_response(
        &mut self,
        expected_method: Method,
        tid: &[u8; 12],
    ) -> Result<StunMessage, SessionError> {
        let deadline = Instant::now() + self.config.stun_timeout;

        loop {
            let rem = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            if rem.is_zero() {
                return Err(SessionError::Timeout);
            }

            let (frame, _) = match self.recv_frame_timeout(rem).await? {
                Some(r) => r,
                None => return Err(SessionError::Timeout),
            };

            match demux(&frame) {
                PacketType::ChannelData => {
                    // Buffer the ChannelData so it isn't lost
                    match ChannelData::decode(&frame) {
                        Ok(cd) => {
                            // Issue 3: cap pending_data to prevent OOM
                            if self.pending_data.len() < MAX_PENDING_DATA {
                                self.pending_data.push_back(cd.data);
                            } else {
                                tracing::warn!("pending_data queue full, dropping channel data");
                            }
                        }
                        Err(e) => {
                            tracing::trace!("ignoring malformed ChannelData during STUN wait: {e}");
                        }
                    }
                    continue;
                }
                PacketType::Stun => {
                    let msg = match StunMessage::decode(&frame) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                    if msg.transaction_id != *tid {
                        continue;
                    }
                    if msg.method != expected_method {
                        return Err(SessionError::UnexpectedResponse {
                            expected: expected_method,
                            got: msg.method,
                        });
                    }
                    return Ok(msg);
                }
                _ => continue,
            }
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn relay_addr(&self) -> Option<SocketAddr> {
        self.allocation.as_ref().map(|a| a.relay_addr)
    }

    pub fn allocation_info(&self) -> Option<&AllocationInfo> {
        self.allocation.as_ref()
    }

    pub fn time_until_expiry(&self) -> Option<Duration> {
        self.allocation.as_ref().map(|a| {
            let total = Duration::from_secs(a.lifetime as u64);
            total
                .checked_sub(a.allocated_at.elapsed())
                .unwrap_or(Duration::ZERO)
        })
    }

    // Issue 12: guard against lifetime 0 to prevent refresh storms
    pub fn needs_allocation_refresh(&self) -> bool {
        self.allocation
            .as_ref()
            .map(|a| {
                a.lifetime > 0
                    && a.allocated_at.elapsed() >= Duration::from_secs(a.lifetime as u64 / 2)
            })
            .unwrap_or(false)
    }

    pub fn needs_permission_refresh(&self) -> bool {
        self.last_permission_refresh
            .map(|t| t.elapsed() >= Duration::from_secs(150))
            .unwrap_or(false)
    }

    pub fn needs_channel_refresh(&self) -> bool {
        self.last_channel_refresh
            .map(|t| t.elapsed() >= Duration::from_secs(250))
            .unwrap_or(false)
    }
}

// Issue 8: detect disconnection via io::ErrorKind rather than string matching
fn is_disconnect_error(e: &anyhow::Error) -> bool {
    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
        matches!(
            io_err.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        )
    } else {
        false
    }
}
