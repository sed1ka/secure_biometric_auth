import 'dart:io';

class AuthMessage {
  AuthMessage({this.title, this.hint, this.reason}) {
    assert(
      !(Platform.isIOS && (reason?.isEmpty ?? true)),
      'iOS requires a reason for biometric prompt.',
    );
    if (Platform.isIOS && (reason?.isEmpty ?? true)) {
      throw ArgumentError('iOS requires a reason for biometric prompt.');
    }

    assert(
      !(Platform.isAndroid && (title?.isEmpty ?? true)),
      'Android requires a title for biometric prompt.',
    );
    if (Platform.isAndroid && (title?.isEmpty ?? true)) {
      throw ArgumentError('Android requires a title for biometric prompt.');
    }
  }

  String? title;
  String? hint;
  String? reason;

  AuthMessage copyWith({String? title, String? hint, String? reason}) =>
      AuthMessage(
        title: title ?? this.title,
        hint: hint ?? this.hint,
        reason: reason ?? this.reason,
      );

  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{};
    map['title'] = title;
    map['hint'] = hint;
    map['reason'] = reason;
    return map;
  }
}
