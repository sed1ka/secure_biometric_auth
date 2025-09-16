import 'package:secure_biometric_auth/data/authenticate_result.dart';
import 'package:secure_biometric_auth/data/register_result.dart';

import '../data/auth_message.dart';
import '../src/secure_biometric_auth_platform_interface.dart';

class SecureBiometricAuth {
  Future<bool> isDeviceSupport() async {
    return SecureBiometricAuthPlatform.instance.isDeviceSupport();
  }

  Future<RegisterResult> register({
    required String challenge,
    required AuthMessage authMessage,
  }) async {
    return SecureBiometricAuthPlatform.instance.register(
      challenge: challenge,
      authMessage: authMessage,
    );
  }

  Future<bool> isRegistered() async {
    return SecureBiometricAuthPlatform.instance.isRegistered();
  }

  Future<AuthenticateResult> authenticate({
    required String challenge,
    required AuthMessage authMessage,
  }) async {
    return SecureBiometricAuthPlatform.instance.authenticate(
      challenge: challenge,
      authMessage: authMessage,
    );
  }

  Future<bool> removeAuthenticate() async {
    return SecureBiometricAuthPlatform.instance.removeAuthenticate();
  }
}
