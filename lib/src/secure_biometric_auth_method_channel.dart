import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:secure_biometric_auth/data/authenticate_result.dart';
import 'package:secure_biometric_auth/data/register_result.dart';
import 'package:secure_biometric_auth/error/secure_biometric_auth_exceptions.dart';

import '/data/auth_message.dart';
import 'secure_biometric_auth_platform_interface.dart';

/// An implementation of [SecureBiometricAuthPlatform] that uses method channels.
class MethodChannelSecureBiometricAuth extends SecureBiometricAuthPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('secure_biometric_auth');

  // Check is registered biometric exist
  Future<bool> isDeviceSupport() async {
    try {
      bool result = await methodChannel.invokeMethod('isDeviceSupport');
      return result;
    } on Exception catch (e) {
      throw parsePlatformException(e);
    }
  }

  // Generate key-pairs if biometric verification is success
  // then return the public-key
  @override
  Future<RegisterResult> register({
    required String challenge,
    required AuthMessage authMessage,
  }) async {
    try {
      final raw = await methodChannel
          .invokeMethod('register', {
        'challenge': challenge,
        'authMessage': authMessage.toJson(),
      });

      final Map<String, dynamic> result = Map<String, dynamic>.from(raw);
      return RegisterResult.fromJson(result);
    } on Exception catch (e) {
      throw parsePlatformException(e);
    }
  }

  // Check is registered biometric exist
  Future<bool> isRegistered() async {
    try {
      bool result = await methodChannel.invokeMethod('isRegistered');
      return result;
    } on Exception catch (e) {
      throw parsePlatformException(e);
    }
  }

  // Generate signature if biometric verification is success
  // then return signature with Base64URL
  @override
  Future<AuthenticateResult> authenticate({
    required String challenge,
    required AuthMessage authMessage,
  }) async {
    try {
      final raw = await methodChannel.invokeMethod(
        'authenticate',
        {
          'challenge': challenge,
          'authMessage': authMessage.toJson(),
        },
      );

      final Map<String, dynamic> result = Map<String, dynamic>.from(raw);
      return AuthenticateResult.fromJson(result);
    } on Exception catch (e) {
      throw parsePlatformException(e);
    }
  }

  // Remove generated key-pairs on local device
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
