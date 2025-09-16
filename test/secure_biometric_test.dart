import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'package:secure_biometric_auth/data/auth_message.dart';
import 'package:secure_biometric_auth/data/authenticate_result.dart';
import 'package:secure_biometric_auth/data/register_result.dart';
import 'package:secure_biometric_auth/src/secure_biometric_auth_method_channel.dart';
import 'package:secure_biometric_auth/src/secure_biometric_auth_platform_interface.dart';

class MockSecureBiometricAuthPlatform
    with MockPlatformInterfaceMixin
    implements SecureBiometricAuthPlatform {
  @override
  Future<AuthenticateResult> authenticate({
    required String challenge,
    required AuthMessage authMessage,
  }) {
    // TODO: implement authenticate
    throw UnimplementedError();
  }

  @override
  Future<bool> isDeviceSupport() {
    // TODO: implement isDeviceSupport
    throw UnimplementedError();
  }

  @override
  Future<bool> isRegistered() {
    // TODO: implement isRegistered
    throw UnimplementedError();
  }

  @override
  Future<RegisterResult> register({
    required String challenge,
    required AuthMessage authMessage,
  }) {
    // TODO: implement register
    throw UnimplementedError();
  }

  @override
  Future<bool> removeAuthenticate() {
    // TODO: implement removeAuthenticate
    throw UnimplementedError();
  }
}

void main() {
  final SecureBiometricAuthPlatform initialPlatform =
      SecureBiometricAuthPlatform.instance;

  test('$MethodChannelSecureBiometricAuth is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelSecureBiometricAuth>());
  });
}
