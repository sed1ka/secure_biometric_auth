class RegisterResult {
  RegisterResult({this.challenge, this.publicKey, this.signature});

  RegisterResult.fromJson(dynamic json) {
    challenge = json['challenge'];
    publicKey = json['publicKey'];
    signature = json['signature'];
  }

  String? challenge;
  String? publicKey;
  String? signature;

  RegisterResult copyWith({
    String? challenge,
    String? publicKey,
    String? signature,
  }) => RegisterResult(
    challenge: challenge ?? this.challenge,
    publicKey: publicKey ?? this.publicKey,
    signature: signature ?? this.signature,
  );

  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{};
    map['challenge'] = challenge;
    map['publicKey'] = publicKey;
    map['signature'] = signature;
    return map;
  }
}
