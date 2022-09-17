
import Crypto
import Foundation

#if os(macOS) || os(iOS)

@_exported import KeychainMacOS

#else

@_exported import KeychainLinux

#endif

public protocol KeychainProtocol: Codable
{
    // Key Agreement
    func generateAndSavePrivateKey(label: String) -> P256.KeyAgreement.PrivateKey?
    func retrievePrivateKey(label: String) -> P256.KeyAgreement.PrivateKey?
    func deleteKey(label: String)

    func retrieveOrGeneratePrivateKey(label: String) -> P256.KeyAgreement.PrivateKey?
    func storePrivateKey(_ key: P256.KeyAgreement.PrivateKey, label: String) -> Bool
    func generateKeySearchQuery(label: String) -> CFDictionary

    // Signing
    func generateAndSavePrivateSigningKey(label: String) -> P256.Signing.PrivateKey?
    func retrievePrivateSigningKey(label: String) -> P256.Signing.PrivateKey?

    func retrieveOrGeneratePrivateSigningKey(label: String) -> P256.Signing.PrivateKey?
    func storePrivateSigningKey(_ key: P256.Signing.PrivateKey, label: String) -> Bool
}

extension Keychain: KeychainProtocol {}
