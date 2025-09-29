/// Represents the result of a biometric registration process.
///
/// Contains the challenge, public key, and signature returned
/// after successfully registering a device biometric credential.
class RegisterResult {
  /// Creates a new [RegisterResult] instance.
  ///
  /// All fields are optional and can be null.
  RegisterResult({this.challenge, this.publicKey, this.signature});

  /// Creates a [RegisterResult] instance from a JSON map.
  ///
  /// Expects the keys: 'challenge', 'publicKey', and 'signature'.
  RegisterResult.fromJson(dynamic json) {
    challenge = json['challenge'];
    publicKey = json['publicKey'];
    signature = json['signature'];
  }

  /// The challenge string returned during registration.
  String? challenge;

  /// The public key generated for the registered biometric credential.
  String? publicKey;

  /// The signature corresponding to the registration challenge.
  String? signature;

  /// Returns a copy of this [RegisterResult] with updated fields.
  ///
  /// Example:
  /// ```dart
  /// final updated = oldResult.copyWith(challenge: "newChallenge");
  /// ```
  RegisterResult copyWith({
    String? challenge,
    String? publicKey,
    String? signature,
  }) =>
      RegisterResult(
        challenge: challenge ?? this.challenge,
        publicKey: publicKey ?? this.publicKey,
        signature: signature ?? this.signature,
      );

  /// Converts this [RegisterResult] into a JSON-compatible map.
  ///
  /// Returns a map with keys 'challenge', 'publicKey', and 'signature'.
  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{};
    map['challenge'] = challenge;
    map['publicKey'] = publicKey;
    map['signature'] = signature;
    return map;
  }
}
