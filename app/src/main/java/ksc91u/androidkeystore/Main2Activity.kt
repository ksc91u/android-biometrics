package ksc91u.androidkeystore

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.google.android.material.snackbar.Snackbar
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt

import kotlinx.android.synthetic.main.activity_main2.*
import kotlinx.android.synthetic.main.content_main2.*
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class Main2Activity : AppCompatActivity() {

    private var encrypted: ByteArray? = null


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main2)
        setSupportActionBar(toolbar)

        var iv = ByteArray(16)
        SecureRandom().nextBytes(iv)

        encryptBtn.setOnClickListener {

            val key = getAESKey("key2")
            val cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7
            )
                .apply {
                    // java.lang.IllegalStateException: Crypto primitive not initialized
                    // init(Cipher.ENCRYPT_MODE, key)

                    /* OR */

                    // android.security.keystore.UserNotAuthenticatedException: User not authenticated
                    //init(Cipher.ENCRYPT_MODE, key)
                }

            val biometricPrompt = BiometricPrompt(
                this@Main2Activity,
                this@Main2Activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                    }

                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        val cipher2 = result.cryptoObject?.cipher
                        cipher2?.let {
                            encrypted = it.doFinal("Taiwan passes same-sex marriage bill".toByteArray())
                            iv = it.iv
                            tv.text =
                                tv.text.toString() + "\n" + ">>> Taiwan passes same-sex marriage bill -> " + String(
                                    Base64.encode(
                                        encrypted,
                                        Base64.DEFAULT
                                    )
                                )
                            println(
                                ">>> Taiwan passes same-sex marriage bill -> " + String(
                                    Base64.encode(
                                        encrypted,
                                        Base64.DEFAULT
                                    )
                                )
                            )
                        }
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                    }
                }
            )
            val prompt = BiometricPrompt.PromptInfo.Builder().setTitle("Encrypt")
                .setDeviceCredentialAllowed(true)
                .build()
            val cryptObject = BiometricPrompt.CryptoObject(cipher)

            biometricPrompt.authenticate(prompt)

        }

        decryptBtn.setOnClickListener {

        }
    }

    fun getAESKey(keyAlias: String): SecretKey {
        val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
        androidKeyStore.load(null)
        if (androidKeyStore.containsAlias(keyAlias)) {
            return androidKeyStore.getKey(keyAlias, null) as SecretKey
        }


        var keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply {
                val builder = KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                val keySpec = builder.setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setRandomizedEncryptionRequired(true)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(60)
                    .build()
                init(keySpec)
            }
        return keyGenerator.generateKey()
    }

}
