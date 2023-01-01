package io.github.toquery.example.spring.authorization.server.core.properties;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author ToQuery
 */
@Slf4j
@Data
@ConfigurationProperties(
        prefix = "app.oauth"
)
public class OAuthAuthorizationProperties {

    private String keyId = "123456";

    private String publicKey = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAubchnOTygr7dxlrj4NvM
            aBz1eFzenDoEjYgAMI6E0dTy+HDT9ZN5ZxDXHo1Yt/ZbQtAvNPkgWSx7ZeFvMPEK
            yNOv8KjAPJUEfvY6WJM4GneO2t3dQAJ2tm4Fbj7n/+dfWo+7/JIIx+fcBipY6Ot7
            sZcavoupjFTzlNLAwHKVGaqKjsV4YV4cLlLwBaZGP7yzujWGGy/rU1NhlQR9h5bd
            SmUALOS33R6LOtLvJZUJgWrF4Ygmdl2ut3A9tGwLmkjWnKozW3qWvRPscT2LYpCV
            MpNALy4JHDrxI+cTOX61f7eAj2KSnQdfMXdwFhrlcW3ZTRRwCMP7xSfhJ+vssG8n
            4QIDAQAB
            -----END PUBLIC KEY-----
            """;

    private String privateKey = """
            -----BEGIN PRIVATE KEY-----
            MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQC5tyGc5PKCvt3G
            WuPg28xoHPV4XN6cOgSNiAAwjoTR1PL4cNP1k3lnENcejVi39ltC0C80+SBZLHtl
            4W8w8QrI06/wqMA8lQR+9jpYkzgad47a3d1AAna2bgVuPuf/519aj7v8kgjH59wG
            Kljo63uxlxq+i6mMVPOU0sDAcpUZqoqOxXhhXhwuUvAFpkY/vLO6NYYbL+tTU2GV
            BH2Hlt1KZQAs5LfdHos60u8llQmBasXhiCZ2Xa63cD20bAuaSNacqjNbepa9E+xx
            PYtikJUyk0AvLgkcOvEj5xM5frV/t4CPYpKdB18xd3AWGuVxbdlNFHAIw/vFJ+En
            6+ywbyfhAgMBAAECggEBALNoTYlyxzA1UKuBPGkKDQJ7D0vSc576kVFkk8JUu8y1
            am9FGA5CBGLjqt0x8QXucSUvVptXG7/pr9+xEyh1g1SU43+alfMwhiJcnerZdbZj
            z1ZyRH3Eo4gC6y4giSD3FG+5MQKC1QbBXxV5rWB9tIXQEp8G7qjJnHIl0t1XE+Cw
            7h9BgoXOmfnnPyXOTSIxXkGlsodriFZ+i5+Ya63myHEcnsNtRtphU/cbgplX+FG/
            t3USYGRKy7tvcQ9UccvTLpu/jGDJVyUSWXLm4QhwkpusvHW9+1fCaueRgliLvRx2
            2g1qd3YqBtF4tXSDFpPtg2J+na8R+fYwpzMml9mLdD0CgYEA9rdYnait0bGhnr0m
            FcOq3PL3pgutt8kdqfHFmRvayTgyOjtOe8ghl+84MRItSCM9Bva0zmPi1lSj0yEr
            D++lVtnNcSJTRoMwvUIQxpV8MffMA3vXvZsiXvcnjsVUweOKMpC3faGgXHx9ltUj
            niF/tyR18r6Iaq98NSWdV9SIUgcCgYEAwLQnrKwkHFcbbHGCJ6CXxmwRfyxNZdho
            fMiUVLqGalHtnPhsnyAo3aLsLzbijgEJKsqdjyRy1LSUBfHcwnUkkRuzvqCQYHFs
            YAuYMpLWlQEk+UTH92I6h6ljZu18UuIHdIMsNm5+190cJGK/WBKV3rZo2OKjh6Nm
            5ulzxAranNcCgYEAtahUYGm16oOPTDFbnIThByUDQcixlXRJGjvB0bWXx7dQDF5k
            sHGwgo2KY19N5iLEKZ93i8wyVrwlkCyI54f9xtBCG745cN7iAUhmz8F7m9Mn7Zy/
            QoW6rg/vmYkkmkqvFAJIiQF78P1c/7VaL3Hc9v2qtxyhl2Q04XEbxHLiGPsCgYEA
            lwAUXq/9E+AF8zH2xUqH48nm4/o5I+cx6SXbZZFLpqBQS0I3C3HN0+7ImC6v1Ipn
            PorKb9Il0Rs3KnldfVsBrltAu81hlNEMFS7AslBxqQzehh0pfGYSax+Gbq8FToUj
            Rl9LE9P9vPTcCn7+ZOsbWQsimWDut2iJR8QDHMlMiL0CgYEAuyioPoI+gW7rBOOi
            bwUx+eUIQL1rPYmSXERnQ+qx85EX1/TGprIMk86a9rIEnzegIQQE8txUOOT2gr8i
            PQ9ot3e4//wFiQkV4K6B9q4xQbCaTzE4WB4xolSkpxFGvx+tJf0ozC40IT8/sacz
            2eEKYKwwokGTZ5Y+f/ib4u0znDQ=
            -----END PRIVATE KEY-----
            """;


}
