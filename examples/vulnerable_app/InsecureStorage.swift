import Foundation

class DataStorageManager {
    
    // HIGH: Storing password in UserDefaults
    func saveCredentials(username: String, password: String) {
        UserDefaults.standard.set(username, forKey: "username")
        UserDefaults.standard.set(password, forKey: "password")
    }
    
    // HIGH: Storing API key in UserDefaults
    func saveAPIKey(_ apiKey: String) {
        UserDefaults.standard.set(apiKey, forKey: "api_key")
    }
    
    // HIGH: Storing auth token in UserDefaults
    func saveAuthToken(_ token: String) {
        UserDefaults.standard.set(token, forKey: "auth_token")
    }
    
    // MEDIUM: Logging sensitive data
    func loginUser(username: String, password: String) {
        print("Logging in user: \(username) with password: \(password)")
        NSLog("Auth attempt - password: \(password)")
        
        // Authentication logic here
    }
    
    // MEDIUM: Logging credit card info
    func processPurchase(cardNumber: String, cvv: String) {
        print("Processing card: \(cardNumber), CVV: \(cvv)")
    }
    
    // HIGH: Writing sensitive data to file without protection
    func saveSensitiveData(data: String) {
        let fileURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("sensitive.txt")
        
        try? data.write(to: fileURL, atomically: true, encoding: .utf8)
    }
    
    // MEDIUM: Using no file protection
    func createUnprotectedFile() {
        let fileURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("data.db")
        
        let attributes = [FileAttributeKey.protectionKey: FileProtectionType.none]
        
        FileManager.default.createFile(atPath: fileURL.path, 
                                      contents: nil, 
                                      attributes: attributes)
    }
    
    // Correct way (commented out for comparison)
    /*
    func saveCredentialsSecurely(username: String, password: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: username,
            kSecValueData as String: password.data(using: .utf8)!
        ]
        
        SecItemAdd(query as CFDictionary, nil)
    }
    */
}