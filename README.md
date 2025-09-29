

# secure_biometric_auth
A flutter plugin for secure biometric authentication on iOS and Android, with key-pair generation, challenge-based verification, and detailed error handling.

|             | Android | iOS   |
|-------------|---------|-------|
| **Support** | SDK 21+ | 15.0+ |



## Features
- Uses **StrongBox** on compatible Android devices and **Secure Enclave** on iOS to store cryptographic keys securely.
- Cryptography:
  - **Android:** ECC primary, fallback to RSA (SHA256withRSA/PSS) if ECC generation fails
  - **iOS:** Only ECC (SHA256withECDSA)
- Customizable UI components for signature prompts 
- High-level abstractions for managing biometric signatures
- Detailed Error Handling.


## Installation

Add the dependency in your pubspec.yaml:
```
dependencies:  
secure_biometric_auth: ^0.0.2
```  
Then run:
  ```
flutter pub get  
  ```

## Usage

### Android Integration
#### Activity Changes
This plugin requires the use of a `FragmentActivity` as opposed to Activity. This can be easily done by switching to use `FlutterFragmentActivity` as opposed to `FlutterActivity` in your manifest or your own Activity class if you are extending the base class.

The `MainActivity` file is usually located in the `android/app/src/main/kotlin` folder if you are using Kotlin, or in the `android/app/src/main/java` folder if you are using Java.
For example:
```
package com.example.myapp  
  
import io.flutter.embedding.android.FlutterFragmentActivity  
  
class MainActivity : FlutterFragmentActivity()
```

#### Permissions
Update your project's `AndroidManifest.xml` file to include the `USE_BIOMETRIC` permission.
```
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    
    // Add USE_BIOMETRIC permision
    <uses-permission android:name="android.permission.USE_BIOMETRIC" />
    
</manifest>
```

### iOS Integration
Add this in to your `Info.plist` file.
```
<key>NSFaceIDUsageDescription</key>
<string>This app is using FaceID for authentication</string>
```

### Import the plugin
```
import 'package:secure_biometric_auth/secure_biometric_auth.dart'; 
```

###  Check if device supports biometric
Checks whether the device supports biometric authentication. Returns `true` if supported, `false`
otherwise.
```
bool isSupported = await SecureBiometricAuth.isDeviceSupport();  
```


### Check if biometric is already registered
Checks if the user has already registered biometric credentials.  
Useful to determine whether to proceed with registration or directly authenticate.
```
bool isRegistered = await SecureBiometricAuth.isRegistered();  
```

### Register biometric credentials
Registers a new biometric credential using a **server-provided challenge**.
Returns a `publicKey` and a `signature` that should be sent to the backend for verification. Always wrap in `try/catch` to handle `SecureBiometricException`.
```
final challenge = "server-generated-challenge-string";
final authMessage = AuthMessage(
  title: "Register Biometric",
  subtitle: "Use your fingerprint or face",
  description: "Secure registration of biometric keys",
);

try {  
  final registerResult = await SecureBiometricAuth.register(
    challenge: challenge,
    authMessage: authMessage,
  );
  final publicKey = registerResult.publicKey;
  final signature = registerResult.signature;
} on SecureBiometricAuthException catch (e) {
  print('Error: ${e.type}, ${e.message}');
}
```

### Authenticate
Verifies the user using previously registered biometric credentials. Signs the server challenge
using the **securely stored private key**. Send the returned `signature` to the backend for validation.
```
final challenge = "server-generated-challenge-string";
final authMessage = AuthMessage(
  title: "Authenticate",
  subtitle: "Use your fingerprint or face",
  description: "Authenticate securely",
);

try {  
  final result = await SecureBiometricAuth.authenticate(
    challenge: challenge,
    authMessage: authMessage,
  );
  final signature = result.signature;
} on SecureBiometricAuthException catch (e) {
  print('Error: ${e.type}, ${e.message}');
}
```

### Remove local biometric credentials
Deletes the locally stored biometric key pair. Useful for logout scenarios or resetting biometric
authentication.
```
bool removed = await SecureBiometricAuth.removeAuthenticate();
```


## Cryptography Notes
**Android**:
- Primary key: ECC (SHA256withECDSA).
- Fallback key: RSA (SHA256withRSA/PSS) if ECC generation fails on older devices.
- Keys stored in StrongBox when available (hardware-backed keystore).

**iOS**:
- Only ECC (SHA256withECDSA).
- Keys stored in Secure Enclave (hardware-backed).

**Backend considerations:**
- Backend must verify signatures using the correct algorithm based on the key type.
- Public key and signature formats differ for ECC and RSA.

## Error Handling
`SecureBiometricAuthException` is thrown for various errors, with types:

| **Type**                     | **Description**                                            | 
|------------------------------|------------------------------------------------------------|
| `deviceNotSupported`         | Device does not support biometric                          |
| `invalidArguments`           | Method called with invalid arguments                       |
| `privateKeyIsNotExist`       | Private key not found on device                            |
| `userCancel`                 | User canceled authentication                               |
| `cancel`                     | Authentication canceled (system or plugin)                 |
| `biometricAuthFailed`        | Biometric authentication process failed (fallback default) |
| `biometricInvalidCredential` | User credential did not match (fingerprint/face failed)    |
| `biometricNoneEnrolled`      | No biometric enrolled on device                            |
| `biometricLockout`           | Biometric locked due to too many failed attempts           |
| `unknown`                    | Unknown or unexpected error (any step)                     |
