// The Secure Enclave, for 05's Touch ID approver key (macOS only).
//
// The key is made inside the Secure Enclave and never leaves it. What 05 stores is an opaque
// blob only this Mac's Secure Enclave can use. Every signature needs the person to be present:
// Touch ID, an Apple Watch, or the Mac's login password in the system's own dialog. The Secure
// Enclave enforces that, not 05, so a process running as the user cannot sign without them.
//
// Called from Rust through these C functions. Return codes: 0 done, 1 no Secure Enclave,
// 2 the person cancelled, 3 failed (message in `err`), 4 a buffer is too small,
// 5 the key does not open on this Mac, 6 no way to ask the person (no login session).

import CryptoKit
import Foundation
import LocalAuthentication

private func put(_ text: String, _ out: UnsafeMutablePointer<UInt8>, _ cap: Int) {
  let bytes = Array(text.utf8.prefix(max(cap - 1, 0)))
  bytes.withUnsafeBufferPointer { b in
    if let base = b.baseAddress { out.update(from: base, count: bytes.count) }
  }
  if cap > 0 { out[bytes.count] = 0 }
}

private func code(of error: Error, _ err: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int32 {
  let ns = error as NSError
  put(ns.localizedDescription, err, cap)
  if ns.domain == LAErrorDomain {
    switch ns.code {
    case LAError.userCancel.rawValue, LAError.appCancel.rawValue, LAError.systemCancel.rawValue, LAError.userFallback.rawValue:
      return 2
    case LAError.notInteractive.rawValue:
      return 6
    default:
      return 3
    }
  }
  return 3
}

@_cdecl("use05_se_available")
public func use05_se_available() -> Int32 {
  SecureEnclave.isAvailable ? 1 : 0
}

/// Can this Mac ask for Touch ID itself (a sensor with a fingerprint enrolled), rather than only
/// the login password?
@_cdecl("use05_se_biometry")
public func use05_se_biometry() -> Int32 {
  var error: NSError?
  return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) ? 1 : 0
}

@_cdecl("use05_se_create")
public func use05_se_create(
  _ blob: UnsafeMutablePointer<UInt8>, _ blobCap: Int, _ blobLen: UnsafeMutablePointer<Int>,
  _ pub: UnsafeMutablePointer<UInt8>, _ err: UnsafeMutablePointer<UInt8>, _ errCap: Int
) -> Int32 {
  guard SecureEnclave.isAvailable else { return 1 }
  guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], nil) else {
    put("could not describe the key's access rule", err, errCap)
    return 3
  }
  do {
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    let data = key.dataRepresentation
    guard data.count <= blobCap else { return 4 }
    data.copyBytes(to: blob, count: data.count)
    blobLen.pointee = data.count
    let point = key.publicKey.x963Representation
    guard point.count == 65 else {
      put("unexpected public key size", err, errCap)
      return 3
    }
    point.copyBytes(to: pub, count: 65)
    return 0
  } catch {
    return code(of: error, err, errCap)
  }
}

@_cdecl("use05_se_sign")
public func use05_se_sign(
  _ blob: UnsafePointer<UInt8>, _ blobLen: Int,
  _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
  _ reason: UnsafePointer<CChar>,
  _ sig: UnsafeMutablePointer<UInt8>, _ sigCap: Int, _ sigLen: UnsafeMutablePointer<Int>,
  _ err: UnsafeMutablePointer<UInt8>, _ errCap: Int
) -> Int32 {
  guard SecureEnclave.isAvailable else { return 1 }
  let context = LAContext()
  context.localizedReason = String(cString: reason)
  let key: SecureEnclave.P256.Signing.PrivateKey
  do {
    key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(bytes: blob, count: blobLen), authenticationContext: context)
  } catch {
    _ = code(of: error, err, errCap)
    return 5
  }
  do {
    // CryptoKit hashes the message with SHA-256, as ES256 does.
    let signature = try key.signature(for: Data(bytes: msg, count: msgLen)).derRepresentation
    guard signature.count <= sigCap else { return 4 }
    signature.copyBytes(to: sig, count: signature.count)
    sigLen.pointee = signature.count
    return 0
  } catch {
    return code(of: error, err, errCap)
  }
}
