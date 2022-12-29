package com.bty.platform.oauth.authorization.utils;

import org.springframework.security.converter.RsaKeyConverters;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 */
public class RSAUtils {

    public static RSAPublicKey publicKey(String publicKey) {
        return RsaKeyConverters.x509()
                .convert(
                        new ByteArrayInputStream(
                                publicKey.trim()
                                        .getBytes(StandardCharsets.UTF_8)
                        )
                );
    }

    public static RSAPrivateKey privateKey(String privateKey) {
        return RsaKeyConverters.pkcs8()
                .convert(
                        new ByteArrayInputStream(
                                privateKey
                                        .trim()
                                        .getBytes(StandardCharsets.UTF_8)
                        )
                );
    }
}
