package io.dropwizard.primer.auth.orchestration;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import io.dropwizard.primer.PrimerBundle;
import io.dropwizard.primer.exception.PrimerException;
import lombok.NonNull;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
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

    public HmacKey getHmacPublicKey(String hmacPrivateKey) {
        return new HmacKey(hmacPrivateKey.getBytes(StandardCharsets.UTF_8));
    }

    public RSAPublicKey getRsaPublicKey(String rsaKeyId) {
        RsaJsonWebKey rsaJsonWebKey = getPublicJwk(rsaKeyId);
        return rsaJsonWebKey.getRsaPublicKey();
    }
}
