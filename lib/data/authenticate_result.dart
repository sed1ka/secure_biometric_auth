/// Represents the result of a biometric authentication process.
///
/// Contains the challenge and signature returned after successfully
/// authenticating with a registered device biometric credential.
class AuthenticateResult {
  /// Creates a new [AuthenticateResult] instance.
  ///
  /// Both [challenge] and [signature] are optional and can be null.
  AuthenticateResult({this.challenge, this.signature});

  /// Creates an [AuthenticateResult] instance from a JSON map.
  ///
  /// Expects the keys: 'challenge' and 'signature'.
  AuthenticateResult.fromJson(dynamic json) {
    challenge = json['challenge'];
    signature = json['signature'];
  }

  /// The challenge string returned during authentication.
  String? challenge;

  /// The signature corresponding to the authentication challenge.
  String? signature;

  /// Returns a copy of this [AuthenticateResult] with updated fields.
  ///
  /// Example:
  /// ```dart
  /// final updated = oldResult.copyWith(signature: "newSignature");
  /// ```
  AuthenticateResult copyWith({String? challenge, String? signature}) =>
      AuthenticateResult(
        challenge: challenge ?? this.challenge,
        signature: signature ?? this.signature,
      );

  /// Converts this [AuthenticateResult] into a JSON-compatible map.
  ///
  /// Returns a map with keys 'challenge' and 'signature'.
  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{};
    map['challenge'] = challenge;
    map['signature'] = signature;
    return map;
  }
}
