package io.dropwizard.primer.util;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/***
 Created by mudit.g on May, 2020
 ***/
public class CryptUtil {

    private CryptUtil() {
        throw new IllegalStateException("Utility class");
    }

    public static String tokenDecrypt(final String token,
                                      final SecretKeySpec secretKeySpec,
                                      final GCMParameterSpec ivParameterSpec) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(token)));
        } catch (Exception e) {
            return token;
        }
    }

}
