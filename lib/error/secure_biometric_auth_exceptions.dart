import 'package:flutter/services.dart' show PlatformException;

enum SecureBiometricAuthErrorType {
  /// Device is not support for biometric
  deviceNotSupported,

  /// Invalid arguments. The required parameter is missing
  invalidArguments,

  /// Private key is not exist anymore on this device
  privateKeyIsNotExist,

  /// The biometric process is canceled by User
  userCancel,

  /// The biometric process is canceled by System
  cancel,

  /// The biometric authentication process failed due to an internal or unknown reason.
  /// This is the default fallback error returned by the secureBiometric plugin
  /// when authentication cannot be completed successfully.
  biometricAuthFailed,

  /// The biometric authentication has failed.
  /// This can happen when the user fails to authenticate,
  /// e.g., fingerprint does not match or face recognition fails.
  biometricInvalidCredential,

  /// No biometric credentials are enrolled on this device.
  /// The user must register at least one fingerprint or face before authentication.
  biometricNoneEnrolled,

  /// The biometric sensor is temporarily locked due to too many failed attempts.
  /// The user cannot authenticate until the lockout period expires.
  biometricLockout,

  /// An unknown or unexpected error occurred in the secureBiometric plugin.
  /// This can happen in any step, such as checking device capabilities or during authentication,
  /// when the specific cause of failure cannot be determined.
  unknown,
}


/// Exception thrown by the [secure_biometric_auth] plugin
/// when biometric authentication fails.
class SecureBiometricAuthException implements Exception {
  /// The type of error that occurred.
  final SecureBiometricAuthErrorType type;

  /// Optional human-readable message describing the error.
  final String? message;

  /// Creates a new [SecureBiometricAuthException] with [type] and optional [message].
  SecureBiometricAuthException(this.type, [this.message]);

  @override
  String toString() => 'BiometricException($type): $message';
}

/// Parses a [PlatformException] thrown by the platform channel
/// and converts it into a [SecureBiometricAuthException] if possible.
///
/// Returns the original exception if it cannot be mapped.
Exception parsePlatformException(Exception e) {
  if (e is PlatformException) {
    switch (e.code) {
      case 'DEVICE_NOT_SUPPORTED':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.deviceNotSupported,
          e.message,
        );
      case 'INVALID_ARGUMENTS':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.invalidArguments,
          e.message,
        );
      case 'PRIVATE_KEY_IS_NOT_EXIST':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.privateKeyIsNotExist,
          e.message,
        );
      case 'USER_CANCEL':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.userCancel,
          e.message,
        );
      case 'CANCEL':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.cancel,
          e.message,
        );
      case 'BIOMETRIC_AUTH_FAILED':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.biometricAuthFailed,
          e.message,
        );
      case 'BIOMETRIC_INVALID_CREDENTIAL':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.biometricInvalidCredential,
          e.message,
        );
      case 'BIOMETRIC_NONE_ENROLLED':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.biometricNoneEnrolled,
          e.message,
        );
      case 'BIOMETRIC_LOCKOUT':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.biometricLockout,
          e.message,
        );
      case 'UNKNOWN_ERROR':
        return SecureBiometricAuthException(
          SecureBiometricAuthErrorType.unknown,
          e.message,
        );
      default:
        return e;
    }
  }

  return e;
}
