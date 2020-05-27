package io.dropwizard.primer.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * @author Sudhir
 */
@Slf4j
public class AesUtils {

    private static final int KEY_SIZE = 128;
    private static final int ITERATION_COUNT = 100;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String CIPHER = "AES/CBC/PKCS5Padding";
    private static final String ALGORITHMS = "PBKDF2WithHmacSHA1";
    private static final String AES = "AES";

    private AesUtils() {
    }

    /**
     * Encrypt with given secret key
     *
     * @param secret
     * @param value
     * @return
     */
    public static String encrypt(String secret, String value) {
        SecretKey key = generateKey(SALT, secret);
        byte[] encrypted = doFinal(1, key, IV, value.getBytes(StandardCharsets.UTF_8));
        return base64(encrypted);
    }

    /**
     * decrypt already encrypted data
     *
     * @param secret
     * @param encryptedValue
     * @return
     */
    public static String decrypt(String secret, String encryptedValue) {
        SecretKey key = generateKey(SALT, secret);
        byte[] decrypted = doFinal(2, key, IV, base64(encryptedValue));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static byte[] doFinal(int encryptMode, SecretKey key, String iv, byte[] bytes) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(encryptMode, key, new IvParameterSpec(hex(iv)));
            return cipher.doFinal(bytes);
        } catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException var5) {
            throw fail(var5);
        }
    }

    private static SecretKey generateKey(String salt, String secret) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHMS);
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), hex(salt), ITERATION_COUNT, KEY_SIZE);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException var4) {
            throw fail(var4);
        }
    }

    private static String base64(byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    private static byte[] base64(String str) {
        return Base64.decodeBase64(str);
    }

    private static byte[] hex(String str) {
        try {
            return Hex.decodeHex(str.toCharArray());
        } catch (DecoderException var2) {
            throw new IllegalStateException(var2);
        }
    }

    private static IllegalStateException fail(Exception e) {
        return new IllegalStateException(e);
    }
}
