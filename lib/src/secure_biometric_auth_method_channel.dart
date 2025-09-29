import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:secure_biometric_auth/data/authenticate_result.dart';
import 'package:secure_biometric_auth/data/register_result.dart';
import 'package:secure_biometric_auth/error/secure_biometric_auth_exceptions.dart';
import '/data/auth_message.dart';
import 'secure_biometric_auth_platform_interface.dart';

/// An implementation of [SecureBiometricAuthPlatform] that uses method channels
/// to communicate with the native platform (iOS/Android).
class MethodChannelSecureBiometricAuth extends SecureBiometricAuthPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('secure_biometric_auth');

  /// Checks whether the device supports biometric authentication.
  ///
  /// Returns `true` if biometrics are supported, `false` otherwise.
  /// Throws [SecureBiometricAuthException] for platform-specific errors.
  Future<bool> isDeviceSupport() async {
    try {
      bool result = await methodChannel.invokeMethod('isDeviceSupport');
      return result;
    } on Exception catch (e) {
      throw parsePlatformException(e);
    }
  }

  /// Registers a new biometric credential on the device.
  ///
  /// [challenge] is a string used to generate a secure key pair.
  /// [authMessage] contains platform-specific messages displayed
  /// during the biometric prompt.
  ///
  /// Returns a [RegisterResult] containing the challenge, public key,
  /// and signature.
  /// Throws [SecureBiometricAuthException] if registration fails.
  @override
  Future<RegisterResult> register({
    required String challenge,
    required AuthMessage authMessage,
  }) async {
    try {
      final raw = await methodChannel.invokeMethod('register', {
        'challenge': challenge,
        'authMessage': authMessage.toJson(),
      });

      final Map<String, dynamic> result = Map<String, dynamic>.from(raw);
      return RegisterResult.fromJson(result);
    } on Exception catch (e) {
      throw parsePlatformException(e);
    }
  }

  /// Checks whether a biometric credential is already registered on the device.
  ///
  /// Returns `true` if a biometric key exists, `false` otherwise.
  /// Throws [SecureBiometricAuthException] for platform-specific errors.
  Future<bool> isRegistered() async {
    try {
      bool result = await methodChannel.invokeMethod('isRegistered');
      return result;
    } on Exception catch (e) {
      throw parsePlatformException(e);
    }
  }

  /// Authenticates the user using the registered biometric credential.
  ///
  /// [challenge] is a string used to validate the biometric authentication.
  /// [authMessage] contains platform-specific messages displayed during the biometric prompt.
  ///
  /// Returns an [AuthenticateResult] containing the challenge and signature.
  /// Throws [SecureBiometricAuthException] if authentication fails.
  @override
  Future<AuthenticateResult> authenticate({
    required String challenge,
    required AuthMessage authMessage,
  }) async {
    try {
      final raw = await methodChannel.invokeMethod('authenticate', {
        'challenge': challenge,
        'authMessage': authMessage.toJson(),
      });

      final Map<String, dynamic> result = Map<String, dynamic>.from(raw);
      return AuthenticateResult.fromJson(result);
    } on Exception catch (e) {
      throw parsePlatformException(e);
    }
  }

  /// Removes the registered biometric authentication from the device.
  ///
  /// Returns `true` if the removal was successful, `false` otherwise.
  /// Throws [SecureBiometricAuthException] if removal fails.
  @override
  Future<bool> removeAuthenticate() async {
    try {
      bool result = await methodChannel.invokeMethod('removeAuthenticate');
      return result;
    } on Exception catch (e) {
      throw parsePlatformException(e);
    }
  }
}
