class AuthenticateResult {
  AuthenticateResult({this.challenge, this.signature});

  AuthenticateResult.fromJson(dynamic json) {
    challenge = json['challenge'];
    signature = json['signature'];
  }

  String? challenge;
  String? signature;

  AuthenticateResult copyWith({String? challenge, String? signature}) =>
      AuthenticateResult(
        challenge: challenge ?? this.challenge,
        signature: signature ?? this.signature,
      );

  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{};
    map['challenge'] = challenge;
    map['signature'] = signature;
    return map;
  }
}
