package io.github.toquery.example.spring.authorization.server;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Slf4j
//@SpringBootTest
class ExampleSpringAuthorizationServerApplicationTests {

    @Test
    void contextLoads() {
    }

    @Test
    @SneakyThrows
    public void generateRsaKey() {
        KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
        //获取公钥
        PublicKey publicKey = keyPair.getPublic();
        //获取私钥
        PrivateKey privateKey = keyPair.getPrivate();
        //获取byte数组
        byte[] publicKeyEncode = publicKey.getEncoded();
        byte[] privateKeyEncoded = privateKey.getEncoded();
        //进行Base64编码
        String publicKeyStr = "-----BEGIN PUBLIC KEY-----" + System.lineSeparator() + Base64.getEncoder().encodeToString(publicKeyEncode) + System.lineSeparator() + "-----END PUBLIC KEY-----";
        String privateKeyStr = "-----BEGIN PRIVATE KEY-----" + System.lineSeparator() + Base64.getEncoder().encodeToString(privateKeyEncoded) + System.lineSeparator() + "-----END PRIVATE KEY-----";
        //保存文件

        String path = "/Users/toquery/Projects/ToQuery/example/example-spring-authorization-server/src/main/resources/jwts/";
        Files.writeString(Paths.get(path + "rsa_public.isa"), publicKeyStr, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(Paths.get(path + "rsa_private.isa"), privateKeyStr, StandardOpenOption.TRUNCATE_EXISTING);

    }

}
