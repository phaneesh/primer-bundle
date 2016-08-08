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
import com.github.benmanes.caffeine.guava.CaffeinatedGuava;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.TokenExpiredException;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.cache.LoadingCache;
import io.dropwizard.primer.PrimerBundle;
import io.dropwizard.primer.core.ServiceUser;
import io.dropwizard.primer.core.VerifyResponse;
import io.dropwizard.primer.core.VerifyStaticResponse;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerAuthorization;
import io.dropwizard.primer.model.PrimerAuthorizationMatrix;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.joda.time.Interval;

import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.google.common.base.Optional.fromNullable;

/**
 * @author phaneesh
 */
@Slf4j
public class PrimerAuthorizationRegistry {

    private static Map<String, PrimerAuthorization> authList;

    private static List<String> whiteList;

    private static List<String> urlPatterns;

    private static LoadingCache<String, Optional<Boolean>> blacklistCache;

    private static LoadingCache<TokenKey, JsonWebToken> lruCache;

    private static Duration acceptableClockSkew;

    private static JsonWebTokenParser parser;
    private static HmacSHA512Verifier verifier;


    public static void init(PrimerAuthorizationMatrix matrix,
                            Set<String> whiteListUrls, PrimerBundleConfiguration configuration,
                            JsonWebTokenParser tokenParser, HmacSHA512Verifier tokenVerifier) {
        authList = new HashMap<>();
        whiteList = new ArrayList<>();
        urlPatterns = new ArrayList<>();
        parser = tokenParser;
        verifier = tokenVerifier;
        val urlToAuthMap = new HashMap<String, PrimerAuthorization>();
        val tokenMatch = Pattern.compile("\\{(([^/])+\\})");
        if (matrix != null) {
            matrix.getAuthorizations().forEach(auth -> {
                final String pattern = generatePathExpression(auth.getUrl());
                urlPatterns.add(pattern);
                urlToAuthMap.put(pattern, auth);
            });
            matrix.getStaticAuthorizations().forEach(auth -> {
                final String pattern = generatePathExpression(auth.getUrl());
                urlPatterns.add(pattern);
                urlToAuthMap.put(pattern, auth);
            });
            matrix.getAutoAuthorizations().forEach(auth -> {
                final String pattern = generatePathExpression(auth.getUrl());
                urlPatterns.add(pattern);
                urlToAuthMap.put(pattern, auth);
            });
            Collections.sort(urlPatterns, (o1, o2) -> tokenMatch.matcher(o2).groupCount() - tokenMatch.matcher(o1).groupCount());
            Collections.sort(urlPatterns, (o1, o2) -> o2.compareTo(o1));
            urlPatterns.forEach(pattern -> authList.put(pattern, urlToAuthMap.get(pattern)));
        }
        whiteListUrls.forEach(url -> whiteList.add(generatePathExpression(url)));
        Collections.sort(whiteList, (o1, o2) -> tokenMatch.matcher(o2).groupCount() - tokenMatch.matcher(o1).groupCount());
        Collections.sort(whiteList, (o1, o2) -> o2.compareTo(o1));
        acceptableClockSkew = new Duration(configuration.getClockSkew());
        blacklistCache = CaffeinatedGuava.build(
                Caffeine.newBuilder()
                        .expireAfterWrite(configuration.getCacheExpiry(), TimeUnit.SECONDS)
                        .maximumSize(configuration.getCacheMaxSize()), s -> Optional.of(false));
        lruCache = CaffeinatedGuava.build(
                Caffeine.newBuilder()
                        .expireAfterWrite(configuration.getCacheExpiry(), TimeUnit.SECONDS)
                        .maximumSize(configuration.getCacheMaxSize()), PrimerAuthorizationRegistry::verifyToken);
    }

    private static String generatePathExpression(final String path) {
        return path.replaceAll("\\{(([^/])+\\})", "(([^/])+)");
    }

    public static JsonWebToken authorize(final String path, final String method, final String token) throws ExecutionException {
        return lruCache.get(TokenKey.builder()
                .method(method)
                .path(path)
                .token(token)
                .build());
    }

    public static boolean isWhilisted(final String path) {
        return whiteList.stream()
                .filter(path::matches).findFirst().isPresent();
    }

    private static boolean isAuthorized(final String id, final String method, final String role) {
        return authList.get(id).getRoles().contains(role) && authList.get(id).getMethods().contains(method);
    }

    private static JsonWebToken verify(JsonWebToken webToken, String token, String type) throws PrimerException {
        switch (type) {
            case "dynamic":
                return verify(webToken, token);
            case "static":
                return verifyStatic(webToken, token);
        }
        throw PrimerException.builder()
                .errorCode("PR002")
                .message("Unauthorized")
                .status(401)
                .build();
    }

    private static JsonWebToken verify(JsonWebToken webToken, String token) throws PrimerException {
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
        val result = (!StringUtils.isBlank(verifyResponse.getToken()) && !StringUtils.isBlank(verifyResponse.getUserId()));
        if (!result) {
            blacklist(token);
            throw PrimerException.builder()
                    .errorCode("PR002")
                    .message("Unauthorized")
                    .status(401)
                    .build();
        }
        return webToken;
    }

    private static JsonWebToken verifyStatic(JsonWebToken webToken, String token) throws PrimerException {
        final VerifyStaticResponse verifyStaticResponse = PrimerBundle.getPrimerClient().verify(webToken.claim().issuer(),
                webToken.claim().subject(), token, (String) webToken.claim().getParameter("role"));
        val result = (!StringUtils.isBlank(verifyStaticResponse.getToken()) && !StringUtils.isBlank(verifyStaticResponse.getId()));
        if (!result) {
            blacklist(token);
            throw PrimerException.builder()
                    .errorCode("PR002")
                    .message("Unauthorized")
                    .status(401)
                    .build();
        }
        return webToken;
    }

    private static void checkExpiry(JsonWebToken token) {
        if (token.claim() != null) {
            final Instant now = new Instant();
            final Instant issuedAt = fromNullable(toInstant(token.claim().issuedAt())).or(now);
            final Instant expiration = fromNullable(toInstant(token.claim().expiration())).or(new Instant(Long.MAX_VALUE));
            final Instant notBefore = fromNullable(toInstant(token.claim().notBefore())).or(now);
            if (issuedAt.isAfter(expiration) || notBefore.isAfterNow() || !inInterval(issuedAt, expiration, now)) {
                throw new TokenExpiredException();
            }
        }
    }

    private static JsonWebToken verifyToken(TokenKey tokenKey) throws PrimerException {
        final JsonWebToken webToken = parser.parse(tokenKey.getToken());
        verifier.verifySignature(webToken);
        checkExpiry(webToken);
        final String role = (String) webToken.claim().getParameter("role");
        val index = urlPatterns.stream().filter(tokenKey.getPath()::matches).findFirst();
        if (!index.isPresent())
            throw PrimerException.builder()
                    .errorCode("PR001")
                    .message("Unauthorized")
                    .status(401)
                    .build();
        //Short circuit for method auth failure
        if (!isAuthorized(index.get(), tokenKey.getMethod(), role))
            throw PrimerException.builder()
                    .errorCode("PR001")
                    .message("Unauthorized")
                    .status(401)
                    .build();
        switch (authList.get(index.get()).getType()) {
            case "dynamic":
                return verify(webToken, tokenKey.getToken(), "dynamic");
            case "static":
                return verify(webToken, tokenKey.getToken(), "static");
            case "auto":
                final String type = (String) webToken.claim().getParameter("type");
                return verify(webToken, tokenKey.getToken(), type);
            default:
                throw PrimerException.builder()
                        .errorCode("PR001")
                        .message("Unauthorized")
                        .status(401)
                        .build();
        }
    }

    private static boolean inInterval(Instant start, Instant end, Instant now) {
        final Interval interval = new Interval(start, end);
        final Interval currentTimeWithSkew = new Interval(now.minus(acceptableClockSkew), now.plus(acceptableClockSkew));
        return interval.overlaps(currentTimeWithSkew);
    }

    private static Instant toInstant(Long input) {
        if (input == null) {
            return null;
        }
        return new Instant(input * 1000);
    }

    public static void blacklist(String token) {
        blacklistCache.put(token, Optional.of(true));
    }

}
