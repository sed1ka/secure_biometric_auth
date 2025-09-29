import 'package:secure_biometric_auth/data/authenticate_result.dart';
import 'package:secure_biometric_auth/data/register_result.dart';
import '../data/auth_message.dart';
import '../src/secure_biometric_auth_platform_interface.dart';

/// Main API for the [secure_biometric_auth] plugin.
///
/// Provides methods to check device support, register biometrics,
/// authenticate users, and manage biometric credentials.
class SecureBiometricAuth {
  /// Checks whether the current device supports biometric authentication.
  ///
  /// Returns `true` if the device supports biometrics, `false` otherwise.
  Future<bool> isDeviceSupport() async {
    return SecureBiometricAuthPlatform.instance.isDeviceSupport();
  }

  /// Registers a new biometric credential on the device.
  ///
  /// [challenge] is a string used to generate a secure key pair.
  /// [authMessage] contains platform-specific messages displayed
  /// during the biometric prompt.
  ///
  /// Returns a [RegisterResult] containing the challenge, public key,
  /// and signature.
  Future<RegisterResult> register({
    required String challenge,
    required AuthMessage authMessage,
  }) async {
    return SecureBiometricAuthPlatform.instance.register(
      challenge: challenge,
      authMessage: authMessage,
    );
  }

  /// Checks if the device has already registered a biometric credential.
  ///
  /// Returns `true` if a biometric key is registered, `false` otherwise.
  Future<bool> isRegistered() async {
    return SecureBiometricAuthPlatform.instance.isRegistered();
  }

  /// Authenticates the user using the registered biometric credential.
  ///
  /// [challenge] is a string used to validate the biometric authentication.
  /// [authMessage] contains platform-specific messages displayed
  /// during the biometric prompt.
  ///
  /// Returns an [AuthenticateResult] containing the challenge and signature.
  Future<AuthenticateResult> authenticate({
    required String challenge,
    required AuthMessage authMessage,
  }) async {
    return SecureBiometricAuthPlatform.instance.authenticate(
      challenge: challenge,
      authMessage: authMessage,
    );
  }

  /// Removes the registered biometric authentication from the device.
  ///
  /// Returns `true` if removal was successful, `false` otherwise.
  Future<bool> removeAuthenticate() async {
    return SecureBiometricAuthPlatform.instance.removeAuthenticate();
  }
}
