import Foundation
import CommonCrypto

class CryptoManager {
    
    // HIGH: Using weak MD5 hash
    func hashPasswordMD5(_ password: String) -> String {
        let data = Data(password.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    // HIGH: Using weak SHA1 hash
    func hashPasswordSHA1(_ password: String) -> String {
        let data = Data(password.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    // HIGH: Using DES encryption (weak)
    func encryptWithDES(data: Data, key: Data) -> Data? {
        var cryptData = Data(count: data.count + kCCBlockSizeDES)
        let keyLength = kCCKeySizeDES
        let operation = CCOperation(kCCEncrypt)
        let algorithm = CCAlgorithm(kCCAlgorithmDES)
        let options = CCOptions(kCCOptionPKCS7Padding)
        
        var numBytesEncrypted: size_t = 0
        
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(operation, algorithm, options,
                           keyBytes.baseAddress, keyLength,
                           nil,
                           dataBytes.baseAddress, data.count,
                           cryptBytes.baseAddress, cryptData.count,
                           &numBytesEncrypted)
                }
            }
        }
        
        return cryptStatus == kCCSuccess ? cryptData : nil
    }
    
    // MEDIUM: Using weak random for security token
    func generateSecurityToken() -> String {
        let randomValue = arc4random()
        return "\(randomValue)"
    }
}