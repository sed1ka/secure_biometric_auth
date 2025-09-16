import 'dart:async';

import 'package:flutter/material.dart';
import 'package:secure_biometric_auth/secure_biometric_auth.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(home: HomeView());
  }
}

class HomeView extends StatefulWidget {
  const HomeView({super.key});

  @override
  State<HomeView> createState() => _HomeViewState();
}

class _HomeViewState extends State<HomeView> {
  SecureBiometricAuth secureBiometric = SecureBiometricAuth();
  RegisterResult? registerResult;
  AuthenticateResult? authenticateResult;
  dynamic resIsRegistered;
  dynamic resisDeviceSupport;
  dynamic resRemoveAuth;

  @override
  void initState() {
    super.initState();
  }

  Future<void> register() async {
    try {
      dynamic registerResult = await secureBiometric.register(
        challenge: "T3BlbkFJLUdQVDQvMjAyNQ==",
        authMessage: AuthMessage(
          title: 'Fingerprint Authentication',
          hint: 'Put your finger on the sensor',
          reason: 'For Regist',
        ),
      );

      setState(() {
        this.registerResult = registerResult;
      });
    } catch (e) {
      if (e is SecureBiometricAuthException) {
        if (e.type == SecureBiometricAuthErrorType.biometricNoneEnrolled) {
          showSnackbar(
            message:
                'Please setup your biometric on device setting '
                'to enable biometric login.',
            backgroundColor: Colors.grey,
          );
        }
      }
      showSnackbar(message: 'regist: $e');
    }
  }

  Future<void> auth() async {
    try {
      dynamic authRes = await secureBiometric.authenticate(
        challenge: "u3BlbkFJLUdQVDQvMjAzNQ",
        authMessage: AuthMessage(
          title: 'Fingerprint Authentication',
          hint: 'Put your finger on the sensor',
          reason: 'For Login',
        ),
      );

      setState(() {
        authenticateResult = authRes;
      });
    } catch (e) {
      if (e is SecureBiometricAuthException) {
        if (e.type == SecureBiometricAuthErrorType.privateKeyIsNotExist) {
          showSnackbar(
            message: 'Please register first',
            backgroundColor: Colors.blueGrey,
          );
        }
      }
      showSnackbar(message: 'auth: $e');
    }
  }

  Future<void> isDeviceSupport() async {
    try {
      dynamic isDeviceSupport = await secureBiometric.isDeviceSupport();

      setState(() {
        resisDeviceSupport = isDeviceSupport;
      });
    } catch (e) {
      showSnackbar(message: 'ds: $e');
    }
  }

  Future<void> isRegistered() async {
    try {
      dynamic isRegistered = await secureBiometric.isRegistered();

      setState(() {
        resIsRegistered = isRegistered;
      });
    } catch (e) {
      showSnackbar(message: 'isRegist: $e');
    }
  }

  Future<void> removeAuth() async {
    try {
      dynamic removeAuthenticate = await secureBiometric.removeAuthenticate();

      setState(() {
        resIsRegistered = null;
        registerResult = null;
        authenticateResult = null;
        resRemoveAuth = removeAuthenticate;
      });
    } catch (e) {
      showSnackbar(message: 'removeA: $e');
    }
  }

  void showSnackbar({required String message, Color? backgroundColor}) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          message,
          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 15),
        ),
        backgroundColor: backgroundColor ?? Colors.red,
        duration: Duration(seconds: 10),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(
          'Secure Biometric Auth',
          style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(15, 25, 15, 75),
        child: Column(
          spacing: 20,
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Column(
              spacing: 5,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  'Check Device Support',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 5),
                Text('IsDevice Support: $resisDeviceSupport'),
                const SizedBox(height: 5),
                ElevatedButton(
                  onPressed: () => isDeviceSupport(),
                  child: Text('Check Support'),
                ),
              ],
            ),

            const Divider(thickness: 1),

            Column(
              spacing: 5,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  'Register Check',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 5),
                Text('Is Registered: $resIsRegistered'),
                const SizedBox(height: 5),
                ElevatedButton(
                  onPressed: () => isRegistered(),
                  child: Text('Check Registered'),
                ),
              ],
            ),

            const Divider(thickness: 1),

            Column(
              spacing: 5,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  'Register',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 5),
                Text('registResult.challenge: ${registerResult?.challenge}'),
                Text('registResult.publicKey: ${registerResult?.publicKey}'),
                Text('registResult.signature: ${registerResult?.signature}'),
                const SizedBox(height: 5),
                ElevatedButton(
                  onPressed: () => register(),
                  child: Text('Try Register'),
                ),
              ],
            ),

            const Divider(thickness: 1),

            Column(
              spacing: 5,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  'Authenticate',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 5),
                Text('authResult.challenge: ${authenticateResult?.challenge}'),
                Text('authResult.signature: ${authenticateResult?.signature}'),
                const SizedBox(height: 5),
                ElevatedButton(
                  onPressed: () => auth(),
                  child: Text('Try Authenticate'),
                ),
              ],
            ),

            Column(
              spacing: 5,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text('Remove Auth: $resRemoveAuth'),
                const SizedBox(height: 5),
                ElevatedButton(
                  onPressed: () => removeAuth(),
                  child: Text('Remove Auth'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
