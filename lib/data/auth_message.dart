import 'dart:io';

/// Represents a biometric authentication message for device prompts.
///
/// Contains optional fields to customize the message shown to the user
/// during biometric authentication on iOS and Android devices.
class AuthMessage {
  /// Creates a new [AuthMessage].
  ///
  /// On iOS, [reason] is required and cannot be empty.
  /// On Android, [title] is required and cannot be empty.
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

  /// The title shown in the biometric prompt on Android devices.
  String? title;

  /// An optional hint or message shown to the user.
  String? hint;

  /// The reason for requesting biometric authentication on iOS devices.
  String? reason;

  /// Returns a copy of this [AuthMessage] with updated fields.
  ///
  /// Example:
  /// ```dart
  /// final newMessage = oldMessage.copyWith(title: "New Title");
  /// ```
  AuthMessage copyWith({String? title, String? hint, String? reason}) =>
      AuthMessage(
        title: title ?? this.title,
        hint: hint ?? this.hint,
        reason: reason ?? this.reason,
      );

  /// Converts the [AuthMessage] to a JSON-compatible map.
  ///
  /// Returns a map with keys 'title', 'hint', and 'reason'.
  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{};
    map['title'] = title;
    map['hint'] = hint;
    map['reason'] = reason;
    return map;
  }
}
