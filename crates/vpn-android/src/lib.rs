//! JNI bridge — exposes vpn-core to Android (Kotlin/Java) via JNI.
//!
//! The Android VpnService uses this crate to:
//!   1. Perform the VPN handshake (X25519 key exchange)
//!   2. Encrypt outgoing IP packets and frame them
//!   3. Decode incoming frames and decrypt IP packets
//!
//! All JNI methods map to the Kotlin class:
//!   `com.vpn.protocol.NativeVpnBridge`
//!
//! Built as `libvpn_android.so` for:
//!   aarch64-linux-android, armv7-linux-androideabi, x86_64-linux-android

use std::sync::Mutex;

use bytes::BytesMut;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jlong, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use vpn_core::crypto::{self, NonceCounter};
use vpn_core::framing::{self, Frame, FrameDecoder};
use vpn_core::handshake::{ClientHandshake, ServerHello};

// ── Opaque Handles ───────────────────────────────────────────
//
// We store Rust objects on the heap and pass an opaque pointer (jlong)
// back to Java/Kotlin. The Kotlin side keeps this as a `Long` field
// and passes it into every subsequent JNI call.

/// Handshake state — alive between `initHandshake` and `finishHandshake`.
struct HandshakeHandle {
    keypair: Option<vpn_core::crypto::KeyPair>,
    client_hello_bytes: Vec<u8>,
}

/// Active session state.
struct SessionHandle {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_nonce: NonceCounter,
    recv_nonce: NonceCounter,
    decoder: FrameDecoder,
    assigned_ip: String,
    dns_servers: Vec<String>,
    mtu: u16,
}

fn into_ptr<T>(val: T) -> jlong {
    Box::into_raw(Box::new(Mutex::new(val))) as jlong
}

unsafe fn from_ptr<T>(ptr: jlong) -> Option<&'static Mutex<T>> {
    if ptr == 0 {
        return None;
    }
    Some(unsafe { &*(ptr as *const Mutex<T>) })
}

/// Lock a Mutex, recovering from poison if necessary.
fn lock_or_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

unsafe fn drop_ptr<T>(ptr: jlong) {
    unsafe {
        let _ = Box::from_raw(ptr as *mut Mutex<T>);
    }
}

// ── Handshake JNI ────────────────────────────────────────────

/// com.vpn.protocol.NativeVpnBridge.initHandshake(sessionToken: String): Long
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_initHandshake(
    mut env: JNIEnv,
    _class: JClass,
    token: JString,
) -> jlong {
    let token_str: String = match env.get_string(&token) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let (hello, keypair) = match ClientHandshake::initiate(token_str) {
        Ok(pair) => pair,
        Err(_) => return 0,
    };

    let data = match serde_json::to_vec(&hello) {
        Ok(d) => d,
        Err(_) => return 0,
    };

    // Prepend the 0x04 handshake type byte so the data is ready
    // for length-prefixed framing: [u16 len][0x04][JSON].
    let mut framed = Vec::with_capacity(1 + data.len());
    framed.push(0x04);
    framed.extend_from_slice(&data);

    let handle = HandshakeHandle {
        keypair: Some(keypair),
        client_hello_bytes: framed,
    };

    into_ptr(handle)
}

/// com.vpn.protocol.NativeVpnBridge.getClientHello(handle: Long): ByteArray
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_getClientHello<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let h = match unsafe { from_ptr::<HandshakeHandle>(handle) } {
        Some(h) => h,
        None => return std::ptr::null_mut(),
    };
    let guard = lock_or_recover(h);
    let out = env
        .byte_array_from_slice(&guard.client_hello_bytes)
        .unwrap();
    out.into_raw()
}

/// com.vpn.protocol.NativeVpnBridge.finishHandshake(handle: Long, serverHello: ByteArray): Long
///
/// Returns a session handle (>0) or 0 on error. Frees the handshake handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_finishHandshake(
    env: JNIEnv,
    _class: JClass,
    hs_handle: jlong,
    server_hello_bytes: JByteArray,
) -> jlong {
    let data = match env.convert_byte_array(&server_hello_bytes) {
        Ok(d) => d,
        Err(_) => {
            unsafe { drop_ptr::<HandshakeHandle>(hs_handle) };
            return 0;
        }
    };

    // Strip the 0x04 handshake type byte that the server prepends.
    let json_data = if data.first() == Some(&0x04) {
        &data[1..]
    } else {
        &data[..]
    };

    let server_hello: ServerHello = match serde_json::from_slice(json_data) {
        Ok(sh) => sh,
        Err(_) => {
            unsafe { drop_ptr::<HandshakeHandle>(hs_handle) };
            return 0;
        }
    };

    let keypair = {
        let h = match unsafe { from_ptr::<HandshakeHandle>(hs_handle) } {
            Some(h) => h,
            None => return 0,
        };
        let mut guard = lock_or_recover(h);
        guard.keypair.take()
    };

    // Free handshake handle
    unsafe { drop_ptr::<HandshakeHandle>(hs_handle) };

    let keypair = match keypair {
        Some(kp) => kp,
        None => return 0,
    };

    let (session_keys, tunnel_config) = match ClientHandshake::finalize(server_hello, keypair) {
        Ok(pair) => pair,
        Err(_) => return 0,
    };

    let session = SessionHandle {
        send_key: session_keys.client_key,
        recv_key: session_keys.server_key,
        send_nonce: NonceCounter::new(session_keys.client_iv),
        // Start at counter=1: nonce 0 was already used during handshake
        // to encrypt the TunnelConfig with server_key + server_iv.
        recv_nonce: NonceCounter::new_with_counter(session_keys.server_iv, 1),
        decoder: FrameDecoder::new(),
        assigned_ip: tunnel_config.assigned_ip,
        dns_servers: tunnel_config.dns_servers,
        mtu: tunnel_config.mtu,
    };

    into_ptr(session)
}

// ── Session JNI ──────────────────────────────────────────────

/// Send: encrypt IP packet → frame → wire bytes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_sendPacket<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    session: jlong,
    plaintext: JByteArray,
) -> jbyteArray {
    let data = match env.convert_byte_array(&plaintext) {
        Ok(d) => d,
        Err(_) => return std::ptr::null_mut(),
    };

    let s = match unsafe { from_ptr::<SessionHandle>(session) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let mut guard = lock_or_recover(s);

    let nonce = match guard.send_nonce.next() {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(),
    };

    let ciphertext = match crypto::encrypt(&guard.send_key, &nonce, &data) {
        Ok(ct) => ct,
        Err(_) => return std::ptr::null_mut(),
    };

    let frame = Frame::Data(ciphertext);
    let mut buf = BytesMut::new();
    if framing::encode(&frame, &mut buf).is_err() {
        return std::ptr::null_mut();
    }

    match env.byte_array_from_slice(&buf) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Feed raw bytes from the TLS socket into the frame decoder.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_feedData(
    env: JNIEnv,
    _class: JClass,
    session: jlong,
    data: JByteArray,
) {
    let bytes = match env.convert_byte_array(&data) {
        Ok(d) => d,
        Err(_) => return,
    };

    let s = match unsafe { from_ptr::<SessionHandle>(session) } {
        Some(s) => s,
        None => return,
    };
    let mut guard = lock_or_recover(s);
    // Silently ignore buffer overflow — decoder is reset internally
    let _ = guard.decoder.feed(&bytes);
}

/// Receive: decode next frame → decrypt → plaintext IP packet.
/// Returns null when no complete frame is buffered.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_receivePacket<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    session: jlong,
) -> jbyteArray {
    let s = match unsafe { from_ptr::<SessionHandle>(session) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let mut guard = lock_or_recover(s);

    loop {
        match guard.decoder.decode() {
            Ok(Some(Frame::Data(ct))) => {
                let nonce = match guard.recv_nonce.next() {
                    Ok(n) => n,
                    Err(_) => return std::ptr::null_mut(),
                };
                let plaintext = match crypto::decrypt(&guard.recv_key, &nonce, &ct) {
                    Ok(pt) => pt,
                    Err(_) => return std::ptr::null_mut(),
                };
                return match env.byte_array_from_slice(&plaintext) {
                    Ok(arr) => arr.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
            Ok(Some(_)) => continue, // skip control frames
            Ok(None) => return std::ptr::null_mut(),
            Err(_) => return std::ptr::null_mut(),
        }
    }
}

/// Create a ping frame.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_createPingFrame<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    _session: jlong,
) -> jbyteArray {
    let mut buf = BytesMut::new();
    if framing::encode(&Frame::Ping, &mut buf).is_err() {
        return std::ptr::null_mut();
    }
    match env.byte_array_from_slice(&buf) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get assigned tunnel IP address.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_getAssignedIp<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    session: jlong,
) -> jni::sys::jstring {
    let s = match unsafe { from_ptr::<SessionHandle>(session) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let guard = lock_or_recover(s);
    match env.new_string(&guard.assigned_ip) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get MTU.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_getMtu(
    _env: JNIEnv,
    _class: JClass,
    session: jlong,
) -> jni::sys::jint {
    let s = match unsafe { from_ptr::<SessionHandle>(session) } {
        Some(s) => s,
        None => return 0,
    };
    let guard = lock_or_recover(s);
    guard.mtu as jni::sys::jint
}

/// Get DNS servers (comma-separated).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_getDnsServers<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    session: jlong,
) -> jni::sys::jstring {
    let s = match unsafe { from_ptr::<SessionHandle>(session) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let guard = lock_or_recover(s);
    let csv = guard.dns_servers.join(",");
    match env.new_string(&csv) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Check if there's buffered data in the decoder.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_hasBufferedData(
    _env: JNIEnv,
    _class: JClass,
    session: jlong,
) -> jboolean {
    let s = match unsafe { from_ptr::<SessionHandle>(session) } {
        Some(s) => s,
        None => return JNI_FALSE,
    };
    let guard = lock_or_recover(s);
    if guard.decoder.buffered() > 0 {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Free a session handle. Must be called when the VPN disconnects.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vpn_protocol_NativeVpnBridge_destroySession(
    _env: JNIEnv,
    _class: JClass,
    session: jlong,
) {
    if session != 0 {
        unsafe { drop_ptr::<SessionHandle>(session) };
    }
}
