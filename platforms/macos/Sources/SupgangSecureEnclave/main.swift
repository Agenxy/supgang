import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// supgang/custody/v1: one ASCII line and EOF each way, at most 16384 bytes.
/// All blobs, compressed public keys, 32-byte digests and raw r || s signatures
/// use lowercase hexadecimal on pipes. No payload is accepted in argv.
/// Rust normalizes s before it constructs DeviceSignature.
private enum CustodyWire {
    static let version = "supgang/custody/v1"
    static let name = "supgang-secure-enclave"
    static let maximum = 16_384

    static func request() throws -> [Substring] {
        guard CommandLine.arguments.count == 1 else { throw Refusal.protocolError }
        var bytes = Data()
        while let chunk = try FileHandle.standardInput.read(upToCount: 1024), !chunk.isEmpty {
            guard bytes.count + chunk.count <= maximum else { throw Refusal.protocolError }
            bytes.append(chunk)
        }
        guard bytes.last == 10,
              bytes.dropLast().allSatisfy({ (32...126).contains($0) }),
              let line = String(data: bytes.dropLast(), encoding: .ascii) else {
            throw Refusal.protocolError
        }
        let fields = line.split(separator: " ", omittingEmptySubsequences: false)
        guard fields.first == Substring(version) else { throw Refusal.protocolError }
        return Array(fields.dropFirst())
    }

    static func decode(_ value: Substring, maximum: Int) throws -> Data {
        guard !value.isEmpty, value.count <= maximum * 2, value.count.isMultiple(of: 2),
              value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw Refusal.protocolError
        }
        var result = Data()
        var index = value.startIndex
        while index < value.endIndex {
            let end = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<end], radix: 16) else { throw Refusal.protocolError }
            result.append(byte)
            index = end
        }
        return result
    }

    static func hex(_ bytes: some Sequence<UInt8>) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func respond(_ body: String) {
        FileHandle.standardOutput.write(Data("\(version) \(body)\n".utf8))
    }
}

/// Adapts an already-hashed 32-byte digest. CryptoKit's digest overload signs it
/// once; using the Data overload here would incorrectly hash it a second time.
private struct SupgangDigest: Digest {
    static let byteCount = 32
    let bytes: [UInt8]
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
}

private enum Refusal: Error {
    case protocolError
    case noHardware
    case refused(Int32)
}

private func context() -> LAContext {
    let context = LAContext()
    context.localizedReason = "Approve Supgang device-key signing"
    context.touchIDAuthenticationAllowableReuseDuration = 0
    return context
}

private func generate(presence: Bool) throws -> String {
    guard SecureEnclave.isAvailable else { throw Refusal.noHardware }
    let flags: SecAccessControlCreateFlags = presence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    var error: Unmanaged<CFError>?
    // `AfterFirstUnlock`, not `WhenUnlocked`: measured on this hardware, an
    // unsigned or ad-hoc-signed binary cannot create a `WhenUnlocked` key at all
    // (-25308, AKS policy), and a daemon that must sign while the screen is
    // locked could not use one anyway. `ThisDeviceOnly` keeps it off iCloud.
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags, &error
    ) else {
        let code = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? -1
        throw Refusal.refused(Int32(clamping: code))
    }
    // No SecItem operation, permanent key, token attribute, entitlement or keychain.
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context())
    guard key.dataRepresentation.count <= 4096 else { throw Refusal.protocolError }
    return "generate \(CustodyWire.hex(key.dataRepresentation)) \(CustodyWire.hex(key.publicKey.compressedRepresentation))"
}

private func run(_ fields: [Substring]) throws -> String {
    if fields == ["probe"] {
        return "probe \(CustodyWire.name) \(SecureEnclave.isAvailable ? "ready" : "no-hardware")"
    }
    if fields == ["generate", "--presence"] { return try generate(presence: true) }
    if fields == ["generate", "--no-presence"] { return try generate(presence: false) }
    guard fields.count == 3 || fields.count == 4, fields[1] == "--sealed" else {
        throw Refusal.protocolError
    }
    guard (fields[0] == "public" && fields.count == 3) || (fields[0] == "sign" && fields.count == 4) else {
        throw Refusal.protocolError
    }
    let blob = try CustodyWire.decode(fields[2], maximum: 4096)
    let digest = fields.count == 4 ? try CustodyWire.decode(fields[3], maximum: 32) : nil
    if let digest, digest.count != 32 { throw Refusal.protocolError }
    guard SecureEnclave.isAvailable else { throw Refusal.noHardware }
    let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context())
    if fields[0] == "public" { return "public \(CustodyWire.hex(key.publicKey.compressedRepresentation))" }
    guard let digest else { throw Refusal.protocolError }
    let signature = try key.signature(for: SupgangDigest(bytes: Array(digest)))
    return "sign \(CustodyWire.hex(signature.rawRepresentation))"
}

private func refusal(_ error: Error) -> String {
    switch error {
    case Refusal.protocolError: return "protocol"
    case Refusal.noHardware: return "no-hardware"
    case Refusal.refused(let code): return "refused \(code)"
    case CryptoKitError.underlyingCoreCryptoError(let code):
        return code == errSecUserCanceled ? "owner-declined-presence" : "refused \(code)"
    default:
        let native = error as NSError
        if native.domain == LAError.errorDomain,
           [LAError.userCancel.rawValue, LAError.appCancel.rawValue, LAError.systemCancel.rawValue].contains(native.code) {
            return "owner-declined-presence"
        }
        if native.domain == NSOSStatusErrorDomain && native.code == Int(errSecUserCanceled) {
            return "owner-declined-presence"
        }
        // No localized descriptions: native errors may contain private material.
        return "refused \(Int32(clamping: native.code))"
    }
}

do {
    CustodyWire.respond("ok \(try run(CustodyWire.request()))")
} catch {
    CustodyWire.respond("error \(refusal(error))")
}
