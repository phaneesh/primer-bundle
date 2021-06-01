/*
 * Copyright 2016 Phaneesh Nagaraja <phaneesh.n@gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.dropwizard.primer.auth;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.base.Strings;
import io.dropwizard.primer.PrimerBundle;
import io.dropwizard.primer.auth.orchestration.KeyOrchestrator;
import io.dropwizard.primer.core.ServiceUser;
import io.dropwizard.primer.core.VerifyResponse;
import io.dropwizard.primer.core.VerifyStaticResponse;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerAuthorization;
import io.dropwizard.primer.model.PrimerAuthorizationMatrix;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import java.security.Key;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * @author phaneesh
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class PrimerAuthorizationRegistry {

    private static Map<String, PrimerAuthorization> authList;

    private static List<String> whiteList;

    private static List<String> urlPatterns;

    private static LoadingCache<String, Optional<Boolean>> blacklistCache;

    private static LoadingCache<TokenKey, JwtClaims> lruCache;

    private static int clockSkew;

    private static String hmacPrivateKey;

    private static KeyOrchestrator keyOrchestrator;

    public static void init(PrimerAuthorizationMatrix matrix, Set<String> whiteListUrls,
                            PrimerBundleConfiguration configuration, KeyOrchestrator jwkKeyOrchestrator) {

        val tokenMatch = Pattern.compile("\\{(([^/])+\\})");

        Map<String, PrimerAuthorization> authList = new HashMap<>();
        List<String> urlPatterns = new ArrayList<>();
        if (matrix != null) {
            if(matrix.getAuthorizations() != null) {
                matrix.getAuthorizations().forEach(auth -> {
                    final String pattern = generatePathExpression(auth.getUrl());
                    urlPatterns.add(pattern);
                    authList.put(pattern, auth);
                });
            }
            if(matrix.getStaticAuthorizations() != null) {
                matrix.getStaticAuthorizations().forEach(auth -> {
                    final String pattern = generatePathExpression(auth.getUrl());
                    urlPatterns.add(pattern);
                    authList.put(pattern, auth);
                });
            }
            if(matrix.getAutoAuthorizations() != null) {
                matrix.getAutoAuthorizations().forEach(auth -> {
                    final String pattern = generatePathExpression(auth.getUrl());
                    urlPatterns.add(pattern);
                    authList.put(pattern, auth);
                });
            }
            urlPatterns.sort((o1, o2) -> tokenMatch.matcher(o2).groupCount() - tokenMatch.matcher(o1).groupCount());
            urlPatterns.sort(Comparator.reverseOrder());
        }

        PrimerAuthorizationRegistry.authList = authList;
        PrimerAuthorizationRegistry.whiteList = primerWhitelistedUrls(whiteListUrls, tokenMatch);
        PrimerAuthorizationRegistry.urlPatterns = urlPatterns;

        blacklistCache = Caffeine.newBuilder()
                .expireAfterWrite(configuration.getCacheExpiry(), TimeUnit.SECONDS)
                .maximumSize(configuration.getCacheMaxSize())
                .build(key -> Optional.of(false));
        lruCache = Caffeine.newBuilder()
                .expireAfterWrite(configuration.getCacheExpiry(), TimeUnit.SECONDS)
                .maximumSize(configuration.getCacheMaxSize())
                .build(PrimerAuthorizationRegistry::verifyToken);

        clockSkew = configuration.getClockSkew();
        hmacPrivateKey = configuration.getPrivateKey();
        keyOrchestrator = jwkKeyOrchestrator;
    }

    private static JwtConsumer getVerificationJwtConsumer(Key key, int secondsOfAllowedClockSkew) {
        return new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(secondsOfAllowedClockSkew)
                .setRequireSubject()
                .setSkipDefaultAudienceValidation()
                .setVerificationKey(key)
                .setJwsAlgorithmConstraints(
                        AlgorithmConstraints.ConstraintType.PERMIT,
                        AlgorithmIdentifiers.HMAC_SHA512, AlgorithmIdentifiers.RSA_USING_SHA256)
                .build();
    }

    private static List<String> primerWhitelistedUrls(Set<String> whiteListUrls, Pattern tokenMatch) {
        List<String> whiteList = new ArrayList<>();

        whiteListUrls.forEach(url -> whiteList.add(generatePathExpression(url)));
        whiteList.sort((o1, o2) -> tokenMatch.matcher(o2).groupCount() - tokenMatch.matcher(o1).groupCount());
        whiteList.sort(Comparator.reverseOrder());
        return whiteList;
    }

    private static String generatePathExpression(final String path) {
        return path.replaceAll("\\{(([^/])+\\})", "(([^/])+)");
    }

    public static JwtClaims authorize(final String path, final String method, final String token, final AuthType authType,
                                      final String primerKeyId) {
        return lruCache.get(TokenKey.builder()
                .method(method)
                .path(path)
                .token(token)
                .authType(authType)
                .primerKeyId(primerKeyId)
                .build());
    }

    public static boolean isWhilisted(final String path) {
        return whiteList.stream()
                .anyMatch(path::matches);
    }

    private static boolean isAuthorized(final String id, final String method, final String role) {
        return authList.get(id).getRoles().contains(role) && authList.get(id).getMethods().contains(method);
    }

    private static JwtClaims verify(JwtClaims jwtClaims, String token, String type) throws PrimerException, MalformedClaimException {
        switch (type) {
            case "dynamic":
                return verifyDynamic(jwtClaims, token);
            case "static":
                return verifyStatic(jwtClaims, token);
        }
        log.debug("invalid_token_type type:{} token:{}", type, token);
        throw PrimerException.builder()
                .errorCode("PR004")
                .message("Unauthorized")
                .status(401)
                .build();
    }

    private static JwtClaims verifyDynamic(JwtClaims jwtClaims, String token) throws PrimerException, MalformedClaimException {
        final VerifyResponse verifyResponse = PrimerBundle.getPrimerClient().verify(
                jwtClaims.getIssuer(),
                jwtClaims.getSubject(),
                token,
                ServiceUser.builder()
                        .id(jwtClaims.getClaimValueAsString("user_id"))
                        .name(jwtClaims.getClaimValueAsString("name"))
                        .role(jwtClaims.getClaimValueAsString("role"))
                        .build()
        );
        val result = (!Strings.isNullOrEmpty(verifyResponse.getToken()) && !Strings.isNullOrEmpty(verifyResponse.getUserId()));
        if (!result) {
            log.debug("dynamic_token_validation_failed token:{} verify_response:{}", token, verifyResponse);
            blacklist(token);
            throw PrimerException.builder()
                    .errorCode("PR004")
                    .message("Unauthorized")
                    .status(401)
                    .build();
        }
        return jwtClaims;
    }

    private static JwtClaims verifyStatic(JwtClaims jwtClaims, String token) throws PrimerException, MalformedClaimException {
        final VerifyStaticResponse verifyStaticResponse = PrimerBundle.getPrimerClient().verify(
                jwtClaims.getIssuer(),
                jwtClaims.getSubject(),
                token,
                jwtClaims.getClaimValueAsString("role"));
        val result = (!Strings.isNullOrEmpty(verifyStaticResponse.getToken()) && !Strings.isNullOrEmpty(verifyStaticResponse.getId()));
        if (!result) {
            log.debug("dynamic_token_validation_failed token:{} verify_response:{}", token, verifyStaticResponse);
            blacklist(token);
            throw PrimerException.builder()
                    .errorCode("PR004")
                    .message("Unauthorized")
                    .status(401)
                    .build();
        }
        return jwtClaims;
    }

    private static JwtClaims verifyConfigAuthToken(TokenKey tokenKey, JwtClaims jwtClaims)
            throws PrimerException, MalformedClaimException {
        final String role = jwtClaims.getClaimValueAsString("role");
        val index = urlPatterns.stream().filter(tokenKey.getPath()::matches).findFirst();
        if (!index.isPresent()) {
            log.debug("No index found for {}", tokenKey);
            throw PrimerException.builder()
                    .errorCode("PR004")
                    .message("Unauthorized")
                    .status(401)
                    .build();
        }
        //Short circuit for method auth failure
        if (!isAuthorized(index.get(), tokenKey.getMethod(), role)) {
            log.debug("Role, method combo check failed for Method={} Role={} Index={}",
                    index.get(), role, tokenKey.getMethod());
            throw PrimerException.builder()
                    .errorCode("PR004")
                    .message("Unauthorized")
                    .status(401)
                    .build();
        }
        switch (authList.get(index.get()).getType()) {
            case "dynamic":
                return verify(jwtClaims, tokenKey.getToken(), "dynamic");
            case "static":
                return verify(jwtClaims, tokenKey.getToken(), "static");
            case "auto":
                final String type = jwtClaims.getClaimValueAsString("type");
                return verify(jwtClaims, tokenKey.getToken(), type);
            default:
                log.debug("invalid_token_type for index:{} token:{}",
                        authList.get(index.get()).getType(), tokenKey);
                throw PrimerException.builder()
                        .errorCode("PR004")
                        .message("Unauthorized")
                        .status(401)
                        .build();
        }
    }

    private static JwtClaims verifyAnnotationAuthToken(TokenKey tokenKey, JwtClaims jwtClaims)
            throws PrimerException, MalformedClaimException {

        final String type = jwtClaims.getClaimValueAsString("type");
        return verify(jwtClaims, tokenKey.getToken(), type);
    }

    private static JwtClaims verifyToken(TokenKey tokenKey)
            throws PrimerException, InvalidJwtException, MalformedClaimException {
        Key key = keyOrchestrator.getPublicKey(hmacPrivateKey, tokenKey.getPrimerKeyId());
        JwtConsumer verificationJwtConsumer = getVerificationJwtConsumer(key, clockSkew);
        JwtClaims jwtClaims = verificationJwtConsumer.processToClaims(tokenKey.getToken());
        switch (tokenKey.getAuthType()) {
            case CONFIG:
                return verifyConfigAuthToken(tokenKey, jwtClaims);
            case ANNOTATION:
                return verifyAnnotationAuthToken(tokenKey, jwtClaims);
            default:
                throw PrimerException.builder()
                        .errorCode("PR004")
                        .message("Unauthorized")
                        .status(401)
                        .build();
        }
    }

    static void blacklist(String token) {
        blacklistCache.put(token, Optional.of(true));
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @EqualsAndHashCode(exclude = {"path", "method", "authType"})
    @ToString
    @Builder
    private static class TokenKey {

        private String token;

        private String path;

        private String method;

        private AuthType authType;

        private String primerKeyId;
    }

}
