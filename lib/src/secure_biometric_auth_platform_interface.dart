import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'package:secure_biometric_auth/data/authenticate_result.dart';
import 'package:secure_biometric_auth/data/register_result.dart';

import '/data/auth_message.dart';
import 'secure_biometric_auth_method_channel.dart';

abstract class SecureBiometricAuthPlatform extends PlatformInterface {
  /// Constructs a SecureBiometricAuthPlatform.
  SecureBiometricAuthPlatform() : super(token: _token);

  static final Object _token = Object();

  static SecureBiometricAuthPlatform _instance = MethodChannelSecureBiometricAuth();

  /// The default instance of [SecureBiometricAuthPlatform] to use.
  ///
  /// Defaults to [MethodChannelSecureBiometricAuth].
  static SecureBiometricAuthPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [SecureBiometricAuthPlatform] when
  /// they register themselves.
  static set instance(SecureBiometricAuthPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<bool> isDeviceSupport() {
    throw UnimplementedError('isDeviceSupport() has not been implemented.');
  }

  Future<RegisterResult> register({
    required String challenge,
    required AuthMessage authMessage,
  }) {
    throw UnimplementedError('register() has not been implemented.');
  }

  Future<bool> isRegistered() {
    throw UnimplementedError('isRegistered() has not been implemented.');
  }

  Future<AuthenticateResult> authenticate({
    required String challenge,
    required AuthMessage authMessage,
  }) {
    throw UnimplementedError('authenticate() has not been implemented.');
  }

  Future<bool> removeAuthenticate() {
    throw UnimplementedError('removeAuthenticate() has not been implemented.');
  }
}
