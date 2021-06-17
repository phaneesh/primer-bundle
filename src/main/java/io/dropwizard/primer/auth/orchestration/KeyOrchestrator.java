package io.dropwizard.primer.auth.orchestration;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.base.Strings;
import io.dropwizard.primer.PrimerBundle;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.key.JwtKey;
import io.dropwizard.primer.model.key.JwtKeyVisitor;
import io.dropwizard.primer.model.key.RsaJwkKey;
import lombok.NonNull;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Map;

/***
 Created by mudit.g on May, 2021
 ***/
public class KeyOrchestrator {

    private final LoadingCache<String, RsaJsonWebKey> jwkPublicKeyLruCache;
    private final ObjectMapper mapper;

    public KeyOrchestrator(final int jwkPublicKeyCacheMaxSize, final ObjectMapper objectMapper) {
        this.jwkPublicKeyLruCache = Caffeine.newBuilder()
                .maximumSize(jwkPublicKeyCacheMaxSize)
                .build(this::getPublicJwkViaNetworkCall);
        this.mapper = objectMapper;
    }

    private RsaJsonWebKey getPublicJwkViaNetworkCall(@NonNull String keyId) throws PrimerException, JoseException {
        JsonNode jwkJson = PrimerBundle.getPrimerClient().getPublicKey(keyId);
        Map<String, Object> jwkMap = mapper.convertValue(jwkJson, new TypeReference<Map<String, Object>>(){});
        return new RsaJsonWebKey(jwkMap);
    }

    private RsaJsonWebKey getPublicJwk(@NonNull String keyId) {
        return jwkPublicKeyLruCache.get(keyId);
    }

    public Key getPublicKey(String hmacPrivateKey, String rsaKeyId) {
        JwtKey jwtKey = getJwtKey(hmacPrivateKey, rsaKeyId);
        return jwtKey.accept(new JwtKeyVisitor<Key>() {
            @Override
            public Key visit(io.dropwizard.primer.model.key.HmacKey hmacKey) {
                return new HmacKey(hmacKey.getPrivateKey().getBytes(StandardCharsets.UTF_8));
            }

            @Override
            public Key visit(RsaJwkKey rsaJwkKey) {
                RsaJsonWebKey rsaJsonWebKey = getPublicJwk(rsaJwkKey.getKeyId());
                return rsaJsonWebKey.getRsaPublicKey();
            }
        });
    }

    private JwtKey getJwtKey(String hmacPrivateKey, String rsaKeyId) {
        if (Strings.isNullOrEmpty(rsaKeyId)) {
            return io.dropwizard.primer.model.key.HmacKey.builder()
                    .privateKey(hmacPrivateKey)
                    .build();
        }
        return RsaJwkKey.builder()
                .keyId(rsaKeyId)
                .build();
    }
}
