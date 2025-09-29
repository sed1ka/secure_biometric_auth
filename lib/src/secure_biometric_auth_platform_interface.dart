import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'package:secure_biometric_auth/data/authenticate_result.dart';
import 'package:secure_biometric_auth/data/register_result.dart';
import '/data/auth_message.dart';
import 'secure_biometric_auth_method_channel.dart';

/// The interface that implementations of `secure_biometric_auth` must implement.
///
/// Platform-specific implementations (iOS/Android) should extend this class
/// and set themselves as the [instance] to enable platform-specific behavior.
///
/// This class uses [PlatformInterface] to enforce that implementations
/// correctly extend it rather than implement it directly.
abstract class SecureBiometricAuthPlatform extends PlatformInterface {
  /// Constructs a SecureBiometricAuthPlatform.
  SecureBiometricAuthPlatform() : super(token: _token);

  static final Object _token = Object();

  static SecureBiometricAuthPlatform _instance =
  MethodChannelSecureBiometricAuth();

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

  /// Checks whether the current device supports biometric authentication.
  ///
  /// Returns `true` if the device supports biometrics, `false` otherwise.
  /// Throws [UnimplementedError] if not implemented on the platform.
  Future<bool> isDeviceSupport() {
    throw UnimplementedError('isDeviceSupport() has not been implemented.');
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
  }) {
    throw UnimplementedError('register() has not been implemented.');
  }

  /// Checks if the device has already registered a biometric credential.
  ///
  /// Returns `true` if a biometric key is registered, `false` otherwise.
  /// Throws [UnimplementedError] if not implemented on the platform.
  Future<bool> isRegistered() {
    throw UnimplementedError('isRegistered() has not been implemented.');
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
  }) {
    throw UnimplementedError('authenticate() has not been implemented.');
  }

  /// Removes the registered biometric authentication from the device.
  ///
  /// Returns `true` if removal was successful, `false` otherwise.
  /// Throws [UnimplementedError] if not implemented on the platform.
  Future<bool> removeAuthenticate() {
    throw UnimplementedError('removeAuthenticate() has not been implemented.');
  }
}
