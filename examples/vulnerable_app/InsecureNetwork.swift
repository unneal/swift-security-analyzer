import Foundation

class NetworkManager {
    
    // HIGH: Hardcoded HTTP URLs (not HTTPS)
    let apiEndpoint = "http://api.example.com/users"
    let imageBaseURL = "http://cdn.myapp.com/images/"
    
    // This is OK - localhost
    let devServer = "http://localhost:3000"
    
    // CRITICAL: Disabled SSL certificate validation
    func setupInsecureSession() -> URLSession {
        let config = URLSessionConfiguration.default
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        return session
    }
    
    func fetchData() {
        guard let url = URL(string: apiEndpoint) else { return }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let data = data {
                print("Received data: \(data)")
            }
        }.resume()
    }
}

// CRITICAL: Accepting all SSL certificates
extension NetworkManager: URLSessionDelegate {
    func urlSession(_ session: URLSession, 
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            // This accepts ALL certificates - very dangerous!
            let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
            completionHandler(.useCredential, credential)
        }
    }
}