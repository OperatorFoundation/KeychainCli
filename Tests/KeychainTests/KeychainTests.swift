import XCTest
@testable import Keychain

final class KeychainTests: XCTestCase
{
    func testSaveAndLoad()
    {
        let url = URL(fileURLWithPath: "keychain")
        guard let keychain = Keychain(baseDirectory: url) else
        {
            XCTFail()
            return
        }

        let key1 = keychain.generateAndSavePrivateKey(label: "test", type: KeyType.P256KeyAgreement)
        let key2 = keychain.retrieveOrGeneratePrivateKey(label: "test", type: KeyType.P256KeyAgreement)

        XCTAssertEqual(key1, key2)    }

    static var allTests = [
        ("testSaveAndLoad", testSaveAndLoad),
    ]
}
