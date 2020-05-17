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
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.validator.ExpiryValidator;
import com.google.common.base.Strings;
import io.dropwizard.primer.PrimerBundle;
import io.dropwizard.primer.core.ServiceUser;
import io.dropwizard.primer.core.VerifyResponse;
import io.dropwizard.primer.core.VerifyStaticResponse;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerAuthorization;
import io.dropwizard.primer.model.PrimerAuthorizationMatrix;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.Duration;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * @author phaneesh
 */
@Slf4j
public class PrimerAuthorizationRegistry {

    private static Map<String, PrimerAuthorization> primerAuthList;

    private static List<String> primerWhitelist;

    private static List<String> primerUrlPatterns;

    private static LoadingCache<String, Optional<Boolean>> blacklistCache;

    private static LoadingCache<TokenKey, JsonWebToken> lruCache;

    private static JsonWebTokenParser parser;
    private static HmacSHA512Verifier verifier;
    private static ExpiryValidator expiryValidator;

    public static void init(PrimerAuthorizationMatrix matrix,
                            Set<String> whiteListUrls, PrimerBundleConfiguration configuration,
                            JsonWebTokenParser tokenParser, HmacSHA512Verifier tokenVerifier) {
        parser = tokenParser;
        verifier = tokenVerifier;

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

        primerAuthList = authList;
        primerWhitelist = primerWhitelistedUrls(whiteListUrls, tokenMatch);
        primerUrlPatterns = urlPatterns;

        expiryValidator = new ExpiryValidator(new Duration(configuration.getClockSkew()));
        blacklistCache = Caffeine.newBuilder()
                .expireAfterWrite(configuration.getCacheExpiry(), TimeUnit.SECONDS)
                .maximumSize(configuration.getCacheMaxSize())
                .build(key -> Optional.of(false));
        lruCache = Caffeine.newBuilder()
                .expireAfterWrite(configuration.getCacheExpiry(), TimeUnit.SECONDS)
                .maximumSize(configuration.getCacheMaxSize())
                .build(PrimerAuthorizationRegistry::verifyToken);
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

    public static JsonWebToken authorize(final String path, final String method, final String token, final AuthType authType) {
        return lruCache.get(TokenKey.builder()
                .method(method)
                .path(path)
                .token(token)
                .authType(authType)
                .build());
    }

    public static boolean isWhilisted(final String path) {
        return primerWhitelist.stream()
                .anyMatch(path::matches);
    }

    private static boolean isAuthorized(final String id, final String method, final String role) {
        return primerAuthList.get(id).getRoles().contains(role) && primerAuthList.get(id).getMethods().contains(method);
    }

    private static JsonWebToken verify(JsonWebToken webToken, String token, String type) throws PrimerException {
        switch (type) {
            case "dynamic":
                return verifyDynamic(webToken, token);
            case "static":
                return verifyStatic(webToken, token);
        }
        log.debug("invalid_token_type type:{} token:{}", type, token);
        throw PrimerException.builder()
                .errorCode("PR004")
                .message("Unauthorized")
                .status(401)
                .build();
    }

    private static JsonWebToken verifyDynamic(JsonWebToken webToken, String token) throws PrimerException {
        final VerifyResponse verifyResponse = PrimerBundle.getPrimerClient().verify(
                webToken.claim().issuer(),
                webToken.claim().subject(),
                token,
                ServiceUser.builder()
                        .id((String) webToken.claim().getParameter("user_id"))
                        .name((String) webToken.claim().getParameter("name"))
                        .role((String) webToken.claim().getParameter("role"))
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
        return webToken;
    }

    private static JsonWebToken verifyStatic(JsonWebToken webToken, String token) throws PrimerException {
        final VerifyStaticResponse verifyStaticResponse = PrimerBundle.getPrimerClient().verify(webToken.claim().issuer(),
                webToken.claim().subject(), token, (String) webToken.claim().getParameter("role"));
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
        return webToken;
    }

    private static JsonWebToken verifyConfigAuthToken(TokenKey tokenKey) throws PrimerException {
        final JsonWebToken webToken = parser.parse(tokenKey.getToken());
        verifier.verifySignature(webToken);
        expiryValidator.validate(webToken);
        final String role = (String) webToken.claim().getParameter("role");
        val index = primerUrlPatterns.stream().filter(tokenKey.getPath()::matches).findFirst();
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
        switch (primerAuthList.get(index.get()).getType()) {
            case "dynamic":
                return verify(webToken, tokenKey.getToken(), "dynamic");
            case "static":
                return verify(webToken, tokenKey.getToken(), "static");
            case "auto":
                final String type = (String) webToken.claim().getParameter("type");
                return verify(webToken, tokenKey.getToken(), type);
            default:
                log.debug("invalid_token_type for index:{} token:{}",
                        primerAuthList.get(index.get()).getType(), tokenKey);
                throw PrimerException.builder()
                        .errorCode("PR004")
                        .message("Unauthorized")
                        .status(401)
                        .build();
        }
    }

    private static JsonWebToken verifyAnnotationAuthToken(TokenKey tokenKey) throws PrimerException {
        final JsonWebToken webToken = parser.parse(tokenKey.getToken());
        verifier.verifySignature(webToken);
        expiryValidator.validate(webToken);

        final String type = (String) webToken.claim().getParameter("type");
        return verify(webToken, tokenKey.getToken(), type);
    }

    private static JsonWebToken verifyToken(TokenKey tokenKey) throws PrimerException {
        switch (tokenKey.getAuthType()) {
            case CONFIG:
                return verifyConfigAuthToken(tokenKey);
            case ANNOTATION:
                return verifyAnnotationAuthToken(tokenKey);
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
    }

}
