package com.sedika.secure_biometric_auth

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAKeyGenParameterSpec
import android.R as AR


const val INCOMPATIBILITY_ACTIVITY = "INCOMPATIBILITY_ACTIVITY"
const val DEVICE_NOT_SUPPORTED = "DEVICE_NOT_SUPPORTED"
const val INVALID_ARGUMENTS = "INVALID_ARGUMENTS"
const val PRIVATE_KEY_IS_NOT_EXIST = "PRIVATE_KEY_IS_NOT_EXIST"
const val USER_CANCEL = "USER_CANCEL"
const val CANCEL = "CANCEL"
const val BIOMETRIC_AUTH_FAILED = "BIOMETRIC_AUTH_FAILED"
const val BIOMETRIC_INVALID_CREDENTIAL = "BIOMETRIC_INVALID_CREDENTIAL"
const val BIOMETRIC_NONE_ENROLLED = "BIOMETRIC_NONE_ENROLLED"
const val BIOMETRIC_LOCKOUT = "BIOMETRIC_LOCKOUT"
const val UNKNOWN_ERROR = "UNKNOWN_ERROR"

enum class AlgorithmType(val type: String, val signatureAlgorithm: String) {
    ECC("ECC_KEY", "SHA256withECDSA"),
    RSA("RSA_KEY", "SHA256withRSA/PSS");

    fun isValidPublicKey(key: PublicKey): Boolean {
        return when (this) {
            ECC -> key is ECPublicKey
            RSA -> key is RSAPublicKey
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun getGenerator(): KeyPairGenerator {
        return when (this) {
            ECC -> KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            RSA -> KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun createKeySpec(context: Context): KeyGenParameterSpec {
        val builder = KeyGenParameterSpec.Builder(this.type, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (this == RSA) {
            builder
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setAlgorithmParameterSpec(
                    RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)
                )
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    builder.setIsStrongBoxBacked(true)
                } catch (e: StrongBoxUnavailableException) {
                    builder.setIsStrongBoxBacked(false)
                }
            }
        }

        return builder.build()
    }

    fun isKeyExist(checkValidity: Boolean): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

            if (!keyStore.containsAlias(type)) return false

            val privateKey = keyStore.getKey(type, null) as? PrivateKey ?: return false
            if (!checkValidity) return true

            val signature = when (this) {
                ECC -> Signature.getInstance("SHA256withECDSA")
                RSA -> Signature.getInstance("SHA256withRSA/PSS")
            }
            signature.initSign(privateKey)

            true
        } catch (e: Exception) {
            false
        }
    }
}

/** SecureBiometricAuthPlugin */
class SecureBiometricAuthPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {
    /// The MethodChannel that will the communication between Flutter and native Android
    ///
    /// This local reference serves to register the plugin with the Flutter Engine and unregister it
    /// when the Flutter Engine is detached from the Activity
    private lateinit var channel: MethodChannel
    private var activity: FlutterFragmentActivity? = null

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FlutterFragmentActivity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        onAttachedToActivity(binding)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        onDetachedFromActivity()
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "secure_biometric_auth")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        if (activity !is FlutterFragmentActivity) {
            result.error(
                INCOMPATIBILITY_ACTIVITY,
                "SecureBiometricAuth requires your app to use FlutterFragmentActivity",
                null
            )
            return
        }

        when (call.method) {
            "isDeviceSupport" -> isDeviceSupport(result)
            "register" -> register(call, result)
            "isRegistered" -> isRegistered(result)
            "authenticate" -> authenticate(call, result)
            "removeAuthenticate" -> removeAuthenticate(result)
            else ->
                result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    private fun isDeviceSupport(result: Result) {
        try {
            val canAuth = isBiometricSupported()
            val canAuthenticate: Boolean =
                canAuth == BiometricManager.BIOMETRIC_SUCCESS ||
                        canAuth == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
            result.success(canAuthenticate)
        } catch (e: Exception) {
            result.error(UNKNOWN_ERROR, e.localizedMessage, null)
        }
    }

    @SuppressLint("Already check the minSdk", "NewApi")
    private fun register(call: MethodCall, result: Result) {
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                result.error(
                    DEVICE_NOT_SUPPORTED,
                    "SecureBiometricAuth minSdk is 23",
                    null
                )
                return
            }

            val challenge = call.argument<String>("challenge") ?: ""
            if (challenge.isEmpty()) {
                result.error(
                    INVALID_ARGUMENTS,
                    "Challenge cant be empty",
                    null
                )
                return
            }

            if (!isValidBase64Url(challenge)) {
                result.error(
                    INVALID_ARGUMENTS,
                    "Challenge required to be Base64URL",
                    null
                )
                return
            }

            val authMessageMap = call.argument<Map<String, String?>>("authMessage")
            val title: String? = authMessageMap?.get("title")
            val hint: String? = authMessageMap?.get("hint")
            val reason: String? = authMessageMap?.get("reason")
            if (title == null) {
                result.error(INVALID_ARGUMENTS, "Title is required", null)
                return
            }


            val canAuth = isBiometricSupported()
            if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
                val errorCode = biometricErrorCodeToString(errorCode = canAuth)
                result.error(
                    errorCode,
                    "Biometric not supported on this device [$canAuth]",
                    null
                )
                return
            }


            // Step 1: Clean up all old keys
            if (isAnyBiometricKeyExist(checkValidity = false)) {
                try {
                    deleteBiometricKey()
                } catch (e: Exception) {
                    result.error(
                        UNKNOWN_ERROR,
                        "Error when deleteBiometric: ${e.localizedMessage}",
                        null
                    )
                }
            }


            // Step 2: Generate Key - try ECC first
            var algorithm = AlgorithmType.ECC
            try {
                generateKey(algorithm)
            } catch (eccError: Exception) {
                try {
                    algorithm = AlgorithmType.RSA
                    generateKey(algorithm)
                } catch (rsaError: Exception) {
                    result.error(
                        UNKNOWN_ERROR,
                        "Error when generate a Key. ${rsaError.localizedMessage}",
                        null
                    )
                    return
                }
            }

            lateinit var cryptoObject: Any
            try {
                val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                val privateKeyEntry =
                    keyStore.getEntry(algorithm.type, null) as? KeyStore.PrivateKeyEntry
                        ?: throw Exception("Private key not found for alias: ${algorithm.type}")
                val privateKey = privateKeyEntry.privateKey

                val signature = Signature.getInstance(algorithm.signatureAlgorithm).apply {
                    initSign(privateKey)
                }
                cryptoObject = BiometricPrompt.CryptoObject(signature)
            } catch (e: Exception) {
                deleteBiometricKey()
                result.error(
                    UNKNOWN_ERROR,
                    "Failed in CryptoObject process: ${e.localizedMessage}",
                    null
                )
                return
            }


            biometricPrompt(
                reasonMessage = reason,
                titleMessage = title,
                hintMessage = hint,
                cryptoObject = cryptoObject,
                onSuccess = { authResult ->
                    val publicKey = getPublicKeyBase64(algorithm = algorithm)
                    val signatureBase64 = signData(
                        challenge = challenge,
                        cryptoObject = authResult.cryptoObject
                    )
                    if (signatureBase64 == null) {
                        deleteBiometricKey()
                        result.error(
                            UNKNOWN_ERROR,
                            "Fail sign a data in auth",
                            null
                        )
                        return@biometricPrompt
                    }

                    val resultData: Map<String, Any?> = mapOf(
                        "challenge" to challenge,
                        "publicKey" to publicKey,
                        "signature" to signatureBase64
                    )
                    result.success(resultData)
                },
                onError = { errCode, errString ->
                    deleteBiometricKey()
                    result.error(
                        errCode,
                        errString,
                        null
                    )
                    return@biometricPrompt
                }
            )
        } catch (e: Exception) {
            result.error(UNKNOWN_ERROR, "Regist failed. ${e.localizedMessage}", null)
        }
    }

    private fun isRegistered(result: Result) {
        try {
            val doesBiometricKeyExist: Boolean = isAnyBiometricKeyExist(checkValidity = true)
            result.success(doesBiometricKeyExist)
        } catch (e: Exception) {
            result.error(
                UNKNOWN_ERROR,
                "Fail to execute isRegistered()",
                e.message ?: "Unknown Error",
            )
        }
    }

    private fun authenticate(call: MethodCall, result: Result) {
        try {
            val challenge = call.argument<String>("challenge") ?: ""
            if (challenge.isEmpty()) {
                result.error(
                    INVALID_ARGUMENTS,
                    "challenge cant be empty",
                    null
                )
                return
            }

            if (!isValidBase64Url(challenge)) {
                result.error(
                    INVALID_ARGUMENTS,
                    "challenge required to be Base64URL",
                    null
                )
                return
            }

            val canAuth = isBiometricSupported()
            if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
                val errorCode = biometricErrorCodeToString(errorCode = canAuth)
                result.error(
                    errorCode,
                    "Biometric not supported on this device [$canAuth]",
                    null
                )
                return
            }

            val authMessageMap = call.argument<Map<String, String?>>("authMessage")
            val title: String? = authMessageMap?.get("title")
            val hint: String? = authMessageMap?.get("hint")
            val reason: String? = authMessageMap?.get("reason")
            if (title == null) {
                result.error(INVALID_ARGUMENTS, "Title is required", null)
                return
            }

            val algorithm = getExistingKeyAlgorithm()
            if (algorithm == null) {
                result.error(
                    PRIVATE_KEY_IS_NOT_EXIST,
                    "No valid private key found. Please register First",
                    null
                )
                return
            }

            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val privateKeyEntry =
                keyStore.getEntry(algorithm.type, null) as? KeyStore.PrivateKeyEntry
            if (privateKeyEntry == null) {
                result.error(
                    PRIVATE_KEY_IS_NOT_EXIST,
                    "Private key not found for alias: ${algorithm.type}. Please register first",
                    null
                )
                return
            }
            val privateKey = privateKeyEntry.privateKey
            val signature = Signature.getInstance(algorithm.signatureAlgorithm).apply {
                initSign(privateKey)
            }
            val cryptoObject = BiometricPrompt.CryptoObject(signature)

            biometricPrompt(
                reasonMessage = reason,
                titleMessage = title,
                hintMessage = hint,
                cryptoObject = cryptoObject,
                onSuccess = { authResult ->
                    try {
                        val signatureBase64 = signData(
                            challenge = challenge,
                            cryptoObject = authResult.cryptoObject
                        )
                        if (signatureBase64 == null) {
                            result.error(
                                BIOMETRIC_AUTH_FAILED,
                                "Fail sign a data in auth. signatureBase64 is null",
                                null
                            )
                        }
                        val resultData: Map<String, Any?> = mapOf(
                            "challenge" to challenge,
                            "signature" to signatureBase64
                        )
                        result.success(resultData)
                    } catch (e: Exception) {
                        result.error(
                            BIOMETRIC_AUTH_FAILED,
                            e.localizedMessage,
                            null
                        )
                        return@biometricPrompt
                    }
                },
                onError = { errCode, errString ->
                    result.error(
                        BIOMETRIC_AUTH_FAILED,
                        "Biometric authentication failed: $errString [$errCode]",
                        null
                    )
                    return@biometricPrompt
                }
            )
        } catch (e: Exception) {
            result.error(
                UNKNOWN_ERROR,
                e.localizedMessage,
                null
            )
        }
    }

    private fun removeAuthenticate(result: Result) {
        try {
            if (isAnyBiometricKeyExist(checkValidity = false)) {
                deleteBiometricKey()
            }
            result.success(true)
        } catch (e: Exception) {
            result.error(UNKNOWN_ERROR, e.localizedMessage, null)
        }
    }

    private fun biometricPrompt(
        titleMessage: String,
        hintMessage: String?,
        reasonMessage: String?,
        cryptoObject: BiometricPrompt.CryptoObject? = null,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        onError: (String, String) -> Unit
    ) {
        try {
            val executor = ContextCompat.getMainExecutor(activity!!)
            val builder = BiometricPrompt.PromptInfo.Builder()
                .setTitle(titleMessage)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText(activity?.getString(AR.string.cancel) ?: "Cancel")

            hintMessage?.let { builder.setSubtitle(it) }
            reasonMessage?.let { builder.setDescription(it) }
            val promptInfo = builder.build()

            val biometricPrompt = BiometricPrompt(
                activity!!,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        onSuccess(result)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        val errorCodeKey = biometricErrorCodeToString(errorCode)
                        onError(errorCodeKey, "$errString [$errorCode]")
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        onError(
                            BIOMETRIC_INVALID_CREDENTIAL,
                            "Invalid credential. Biometric can't be recognized"
                        )
                    }
                }
            )

            if (cryptoObject != null) {
                biometricPrompt.authenticate(promptInfo, cryptoObject)
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        } catch (e: Exception) {
            onError(
                BIOMETRIC_AUTH_FAILED,
                "Fail to execute biometric prompt: ${e.message ?: "Unknown error"}"
            )
        }
    }


    private fun generateKey(algorithm: AlgorithmType) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return

        val spec = algorithm.createKeySpec(activity!!)
        val generator = algorithm.getGenerator()
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    private fun signData(
        challenge: String,
        cryptoObject: BiometricPrompt.CryptoObject?
    ): String? {
        val signatureObj = cryptoObject?.signature ?: return null

        signatureObj.update(challenge.toByteArray(Charsets.UTF_8))
        val signatureBytes = signatureObj.sign()
        return Base64.encodeToString(
            signatureBytes,
            Base64.NO_WRAP
        )
    }


    private fun getPublicKeyBase64(algorithm: AlgorithmType): String {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val publicKey = ks.getCertificate(algorithm.type).publicKey

        if (!algorithm.isValidPublicKey(publicKey)) {
            throw IllegalStateException("Unexpected key type for ${algorithm.name}: ${publicKey.javaClass}")
        }

        val encoded = publicKey.encoded
        return Base64.encodeToString(encoded, Base64.NO_WRAP)
    }

    private fun isValidBase64Url(input: String): Boolean {
        // Cek: hanya karakter base64url (tanpa padding di tengah)
        val base64UrlRegex = Regex("^[A-Za-z0-9_-]*(={0,2})?$")
        if (!base64UrlRegex.matches(input)) return false

        // Cek: panjang harus bisa dibagi 4, atau sisa 2/3 (tanpa padding)
        val remainder = input.length % 4
        return remainder == 0 || remainder == 2 || remainder == 3
    }

    private fun isBiometricSupported(): Int {
        val biometricManager = BiometricManager.from(activity!!)
        val canAuth: Int =
            biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

        return canAuth
    }

    private fun isAnyBiometricKeyExist(checkValidity: Boolean): Boolean {
        try {
            return AlgorithmType.entries.any { it.isKeyExist(checkValidity) }
        } catch (e: Exception) {
            throw e
        }
    }

    private fun getExistingKeyAlgorithm(): AlgorithmType? {
        return AlgorithmType.entries.firstOrNull { it.isKeyExist(checkValidity = true) }
    }

    private fun deleteBiometricKey() {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            AlgorithmType.entries.forEach {
                if (keyStore.containsAlias(it.type)) keyStore.deleteEntry(it.type)
            }
        } catch (e: Exception) {
            throw e
        }
    }


    fun biometricErrorCodeToString(errorCode: Int): String {
        return when (errorCode) {
            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_HW_UNAVAILABLE ->
                DEVICE_NOT_SUPPORTED

            BiometricPrompt.ERROR_NO_BIOMETRICS,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL ->
                BIOMETRIC_NONE_ENROLLED

            BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
            BiometricPrompt.ERROR_LOCKOUT ->
                BIOMETRIC_LOCKOUT

            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_USER_CANCELED ->
                USER_CANCEL

            BiometricPrompt.ERROR_CANCELED,
            BiometricPrompt.ERROR_TIMEOUT ->
                CANCEL

            else -> BIOMETRIC_AUTH_FAILED
        }
    }
}
