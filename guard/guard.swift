import Foundation
import Security
import LocalAuthentication

let service = "co.lesha.bw"
let account = "lesha@lesha.co"
let bw_location = "~/opt/bw"

func expandTilde(in path: String) -> String {
    return (path as NSString).expandingTildeInPath
}

let bw_path = expandTilde(in: bw_location)

class KeychainHelper {
    static let shared = KeychainHelper()
    
    private init() {}
    
    func savePassword(service: String, account: String, password: String) -> Bool {
        guard let passwordData = password.data(using: .utf8) else { return false }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: passwordData
        ]
        
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    func getPassword(service: String, account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess, let passwordData = item as? Data else { return nil }
        return String(data: passwordData, encoding: .utf8)
    }
    
    func deletePassword(service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
}

func authenticateUser() async -> Bool {
    let context = LAContext()
    var error: NSError?
    if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
        let reason = "authenticate"
        return await withCheckedContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, authenticationError in
                continuation.resume(returning: success)
            }
        }
    } else {
        return false
    }
}

func authenticatedRetrieveSession() -> String? {
    return KeychainHelper.shared.getPassword(service: service, account: account)
}

func retrieveSession() async -> String? {
    if await authenticateUser() {
        return authenticatedRetrieveSession()
    } else {
        return nil
    }
}

func runCheck() -> Bool {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: bw_path)
    
    guard let session = authenticatedRetrieveSession() else {
        return false
    }
    
    process.arguments = ["unlock", "--check", "--session", session]
    let outputPipe = Pipe()
    process.standardOutput = outputPipe
    do {
        try process.run()
        process.waitUntilExit()
        if process.terminationStatus == 0 {
            return true
        } else {
            return false
        }
    } catch {
        print("Caught an unexpected error: \(error)")

        return false
    }
}


@main
struct Main {
    static func main() async {
        let arguments = CommandLine.arguments
        switch arguments[1] {
            case "get":
                guard let session = await retrieveSession() else {
                    print("session was not obtained")
                    exit(1)
                }
                print(session)
            case "set":
                let result = KeychainHelper.shared.savePassword(service: service, account: account, password: arguments[2])
                if result{
                    print("session saved successfully")
                    exit(0)
                } else {
                    print("session saved UNccessfully")
                    exit(1)
                }
            case "check":
                if runCheck() {
                    print("session is valid")
                    exit(0)
                } else {
                    print("session is NOT valid")
                    exit(1)
                }

            default:
                exit(2)
        }
    }
}
