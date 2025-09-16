import Flutter
import UIKit
import LocalAuthentication
import Flutter

enum KeyStatusError: Error {
    case unexpectedNil
    case failed(OSStatus)
}

struct Constants {
    static let deviceNotSupported = "DEVICE_NOT_SUPPORTED"
    static let invalidArguments = "INVALID_ARGUMENTS"
    static let privateKeyIsNotAvailable = "PRIVATE_KEY_IS_NOT_EXIST"
    static let userCancel = "USER_CANCEL"
    static let cancel = "CANCEL"
    static let biometricAuthFailed = "BIOMETRIC_AUTH_FAILED"
    static let biometricInvalidCredential = "BIOMETRIC_INVALID_CREDENTIAL"
    static let biometricNoneEnrolled = "BIOMETRIC_NONE_ENROLLED"
    static let biometricLockout = "BIOMETRIC_LOCKOUT"
    static let unknowrnError = "UNKNOWN_ERROR"
    
    
    static var biometricKeyTag: Data {
        let bundleID = Bundle.main.bundleIdentifier ?? "com.sedika.secure_biometric_auth_plugin"
        let tagString = "\(bundleID).biometricKey"
        return tagString.data(using: .utf8)!
    }
}


public class SecureBiometricAuthPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "secure_biometric_auth", binaryMessenger: registrar.messenger())
        let instance = SecureBiometricAuthPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "isDeviceSupport":
            isDeviceSupport(result: result)
        case "register":
            register(call: call, result: result)
        case "isRegistered":
            isRegistered(result: result)
        case "authenticate":
            authenticate(call: call, result: result)
        case "removeAuthenticate":
            removeAuthenticate(result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    func isDeviceSupport(result: @escaping FlutterResult){
        if (isRunningOnSimulator()) {
            dispatchMainAsync { result(false) }
            return
        }
        let availability = checkBiometricAvailability(context: LAContext())
        guard availability.isSupported else {
            if let error  = availability.error as NSError? {
                let code = error.code
                if error is LAError, code == LAError.Code.biometryNotEnrolled.rawValue || code == LAError.passcodeNotSet.rawValue || code == LAError.biometryLockout.rawValue {
                    dispatchMainAsync { result(true) }
                    return
                }
            }
            dispatchMainAsync { result (false) }
            return
        }
        
        dispatchMainAsync { result(availability.isSupported) }
    }
    
    func register(call: FlutterMethodCall, result: @escaping  FlutterResult) {
        if (isRunningOnSimulator()){
            dispatchMainAsync {
                result(
                    FlutterError(
                        code: Constants.deviceNotSupported,
                        message: "Can't run on Simulator",
                        details: nil
                    )
                )
            }
            return
        }
        
        
        // Parsing
        guard let args = call.arguments as? [String: Any] else {
            dispatchMainAsync {
                result(
                    FlutterError(
                        code: Constants.invalidArguments,
                        message: "Arguments missing",
                        details: nil
                    )
                )
            }
            return
        }
        
        // Challenge string Validation
        guard let challenge = args["challenge"] as? String, !challenge.isEmpty else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.invalidArguments, message: "challengeString can't be empty", details: nil))
            }
            return
        }
        guard isValidBase64Url(challenge) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.invalidArguments, message: "challengeString must be Base64URL", details: nil))
            }
            return
        }
        
        let authMessage = args["authMessage"] as? [String: String] ?? [:]
        let reason: String? = authMessage["reason"]
        guard let reason = reason, !reason.isEmpty else {
            dispatchMainAsync {
                result(
                    FlutterError(
                        code: Constants.invalidArguments,
                        message: "Reason is required",
                        details: nil
                    )
                )
            }
            return
        }
        
        let context = LAContext()
        context.localizedFallbackTitle = ""
        
        // Check Biometric support
        let availability = checkBiometricAvailability(context: context)
        guard availability.isSupported else {
            dispatchMainAsync {
                result(self.flutterError(from: availability.error))
            }
            return
        }
        
        
        // Prompt Biometric
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) {
            success,
            error in
            if success {
                do {
                    try self.deleteBiometricKey()
                    try self.generateKey(context: context)
                    let publicKey = try self.getPublicKeyBase64(
                        context: context
                    )
                    let signature = try self.generateSignature(
                        challenge: challenge,
                        context: context
                    )
                    let resultData: [String: Any] = [
                        "challenge": challenge,
                        "publicKey": publicKey,
                        "signature": signature
                    ]
                    self.dispatchMainAsync { result(resultData) }
                } catch {
                    self.dispatchMainAsync {
                        result(self.flutterError(from: error))
                    }
                }
                return
            }
            
            let correctedError = self.overrideWithBiometryLockoutIfUserCancel(
                original: error,
                context: context
            )
            self.dispatchMainAsync {
                result(self.flutterError(from: correctedError))
            }
        }
    }
    
    func isRegistered(result: @escaping FlutterResult) {
        if (isRunningOnSimulator()){
            dispatchMainAsync {
                result(FlutterError(code: Constants.deviceNotSupported, message: "Can't run on Simulator", details: nil))
            }
            return
        }
        
        let hasRegistered = isBiometricKeyExists()
        dispatchMainAsync { result(hasRegistered) }
    }
    
    func authenticate(call: FlutterMethodCall, result: @escaping FlutterResult) {
        if (isRunningOnSimulator()) {
            dispatchMainAsync {
                result(FlutterError(code: Constants.deviceNotSupported, message: "Can't run on Simulator", details: nil))
            }
            return
        }
        
        guard let args = call.arguments as? [String: Any] else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.invalidArguments, message: "Arguments missing", details: nil))
            }
            return
        }
        
        // Challenge string Validtaion
        guard let challenge = args["challenge"] as? String, !challenge.isEmpty else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.invalidArguments, message: "challengeString can't be empty", details: nil))
            }
            return
        }
        guard isValidBase64Url(challenge) else {
            dispatchMainAsync {
                result(FlutterError(code: Constants.invalidArguments, message: "challengeString must be Base64URL", details: nil))
            }
            return
        }
        
        let authMessage = args["authMessage"] as? [String: String] ?? [:]
        let reason: String? = authMessage["reason"]
        guard let reason = reason, !reason.isEmpty else {
            dispatchMainAsync {
                result(
                    FlutterError(
                        code: Constants.invalidArguments,
                        message: "Reason is required",
                        details: nil
                    )
                )
            }
            return
        }
        
        let context = LAContext()
        context.localizedFallbackTitle = ""
        
        // Check biometric availability
        let availability = checkBiometricAvailability(context: context)
        guard availability.isSupported else {
            dispatchMainAsync {
                result(self.flutterError(from: availability.error))
            }
            return
        }
        
        // Check registration
        guard isBiometricKeyExists() else {
            dispatchMainAsync {
                result(
                    FlutterError(
                        code: Constants.privateKeyIsNotAvailable,
                        message: "No valid biometric key found. Please register first.",
                        details: nil
                    )
                )
            }
            return
        }
        
        
        // Prompt biometric
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) {
            success,
            error in
            if success {
                do {
                    let signature = try self.generateSignature(
                        challenge: challenge,
                        context: context
                    )
                    let resultData: [String: Any] = [
                        "challenge": challenge,
                        "signature": signature
                    ]
                    self.dispatchMainAsync { result(resultData) }
                } catch {
                    self.dispatchMainAsync {
                        result(self.flutterError(from: error))
                    }
                }
                return
            }
            
            let correctedError = self.overrideWithBiometryLockoutIfUserCancel(
                original: error,
                context: context
            )
            self.dispatchMainAsync {
                result(self.flutterError(from: correctedError))
            }
        }
    }
    
    func removeAuthenticate(result: @escaping FlutterResult) {
        do {
            guard isBiometricKeyExists() else {
                dispatchMainAsync { result(true) }
                return
            }
            try deleteBiometricKey()
            dispatchMainAsync { result(true) }
        } catch {
            dispatchMainAsync {
                result(FlutterError(code: "REMOVE_AUTHENTICATE_FAILED", message: error.localizedDescription, details: nil))
            }
        }
    }
    
    func checkBiometricAvailability(context: LAContext) -> (isSupported: Bool, error: NSError?) {
        var authError: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError)
        return (canEvaluate, authError)
    }
    
    func isRunningOnSimulator() -> Bool {
        return ProcessInfo().environment["SIMULATOR_DEVICE_NAME"] != nil
    }
    
    func generateKey(context: LAContext) throws {
        var accessError: Unmanaged<CFError>?
        
        guard let access = SecAccessControlCreateWithFlags(nil,
                                                           kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           [.privateKeyUsage, .biometryCurrentSet],
                                                           &accessError) else {
            throw accessError!.takeRetainedValue() as Error
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseAuthenticationContext as String: context,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Constants.biometricKeyTag,
                kSecAttrAccessControl as String: access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            throw error!.takeRetainedValue() as Error
        }
    }
    
    func getPublicKeyBase64(context: LAContext) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Constants.biometricKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let privateKey = item as! SecKey? else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw NSError(domain: NSOSStatusErrorDomain, code: -1, userInfo: nil)
        }
        
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        
        return publicKeyData.base64EncodedString(options: [.endLineWithLineFeed]).replacingOccurrences(of: "\n", with: "")
    }
    
    func generateSignature(challenge: String, context: LAContext) throws -> String {
        guard let privateKey = try getPrivateKey(context: context) else {
            throw NSError(domain: "SIGN_ERROR", code: -1, userInfo: [NSLocalizedDescriptionKey: "Private key not found"])
        }
        
        let base64Challenge = base64urlToBase64(challenge)
        guard let messageData = Data(base64Encoded: base64Challenge, options: .ignoreUnknownCharacters) else {
            throw NSError(domain: "SIGN_ERROR", code: -2, userInfo: [NSLocalizedDescriptionKey: "Invalid base64 payload"])
        }
        
        var error: Unmanaged<CFError>?
        guard let signatureData = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            messageData as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        
        return signatureData.base64EncodedString()
    }
    
    func deleteBiometricKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Constants.biometricKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
        }
    }
    
    func getPrivateKey(context: LAContext) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Constants.biometricKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        case errSecAuthFailed, -25293:
            // Consider key corrupt or not usable, delete it
            SecItemDelete(query as CFDictionary)
            return nil
        default:
            throw KeyStatusError.failed(status)
        }
    }
    
    func isBiometricKeyExists() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Constants.biometricKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnData as String: false,
            kSecReturnRef as String: false
        ]
        
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
    
    func isValidBase64Url(_ input: String) -> Bool {
        // Check Regex
        let pattern = "^[A-Za-z0-9_-]*={0,2}$"
        guard let _ = input.range(of: pattern, options: .regularExpression) else {
            return false
        }
        
        // Check Length
        let remainder = input.count % 4
        return remainder == 0 || remainder == 2 || remainder == 3
    }
    
    private func base64urlToBase64(_ base64url: String) -> String {
        var base64 = base64url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddingLength = 4 - base64.count % 4
        if paddingLength < 4 {
            base64 += String(repeating: "=", count: paddingLength)
        }
        return base64
    }
    
    
    private func dispatchMainAsync(_ block: @escaping () -> Void) {
        DispatchQueue.main.async(execute: block)
    }
    
    func overrideWithBiometryLockoutIfUserCancel(original error: Error?, context: LAContext) -> Error? {
        guard let nsError = error as NSError?,
              nsError.domain == LAError.errorDomain,
              nsError.code == LAError.Code.userCancel.rawValue else {
            return error
        }
        var evalError: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &evalError)
        
        if !canEvaluate,
           let evalCode = evalError?.code,
           evalCode == LAError.biometryLockout.rawValue {
            return evalError
        }
        
        return error
    }
    
    func flutterError(from error: Error?) -> FlutterError {
        guard let error = error else {
            return FlutterError(
                code: Constants.unknowrnError,
                message: "Unknown error occurred",
                details: nil
            )
        }
        
        // Cast to NSError
        guard let nsError = error as NSError? else {
            return FlutterError(
                code: Constants.unknowrnError,
                message: error.localizedDescription,
                details: nil
            )
        }
        
        guard nsError.domain == LAError.errorDomain,
              let laErrorCode = LAError.Code(rawValue: nsError.code) else {
            return FlutterError(
                code: Constants.unknowrnError,
                message: nsError.localizedDescription,
                details: nil
            )
        }
        
        let code: String
        switch laErrorCode {
        case .authenticationFailed: code = Constants.biometricInvalidCredential
        case .userCancel: code = Constants.userCancel
        case .appCancel, .systemCancel: code = Constants.cancel
        case .biometryNotAvailable: code = Constants.deviceNotSupported
        case .biometryNotEnrolled,.passcodeNotSet: code = Constants.biometricNoneEnrolled
        case .biometryLockout: code = Constants.biometricLockout
        default: code = Constants.biometricAuthFailed
        }
        
        return FlutterError(code: code, message: nsError.localizedDescription, details: nil)
    }
}
