package ksc91u.androidkeystore

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.content_main.*
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class MainActivity : AppCompatActivity() {
    private var encrypted:ByteArray? = null

    @SuppressLint("NewApi")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        var iv = ByteArray(16)
        SecureRandom().nextBytes(iv)

        encryptBtn.setOnClickListener {
            val key = getAESKey("helloworld")
            val cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .apply {
                    init(Cipher.ENCRYPT_MODE, key)
                }

            encrypted = cipher.doFinal("Taiwan passes same-sex marriage bill".toByteArray())
            iv = cipher.iv
            tv.text = tv.text.toString() + "\n" + ">>> Taiwan passes same-sex marriage bill -> " + String(Base64.encode(encrypted, Base64.DEFAULT))
            println(">>> Taiwan passes same-sex marriage bill -> " + String(Base64.encode(encrypted, Base64.DEFAULT)))
        }

        decryptBtn.setOnClickListener {
            val key = getAESKey("helloworld")
            val cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .apply {
                    init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
                }

            encrypted?.let{
                val decrypted = cipher.doFinal(it)
                tv.text = tv.text.toString() + "\n" + ">>>> decrypt ${String(Base64.encode(encrypted, Base64.DEFAULT))} -> " + String(decrypted)
                println(">>>> decrypt ${String(Base64.encode(encrypted, Base64.DEFAULT))} -> " + String(decrypted))
            }
        }

        next.setOnClickListener {
            this@MainActivity.startActivity(Intent(this@MainActivity, Main2Activity::class.java))
        }
    }



    private fun showMessage(message: String) {
        Toast
            .makeText(
                this@MainActivity,
                message,
                Toast.LENGTH_SHORT
            )
            .show()
    }

    fun getAESKey(keyAlias: String): SecretKey {
        val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
        androidKeyStore.load(null)
        if (androidKeyStore.containsAlias(keyAlias)) {
            return androidKeyStore.getKey(keyAlias, null) as SecretKey
        }


        var keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply {
                val builder = KeyGenParameterSpec.Builder(keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                val keySpec = builder.setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setRandomizedEncryptionRequired(true)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(3600)
                    .build()
                init(keySpec)
            }
        return keyGenerator.generateKey()
    }
}
