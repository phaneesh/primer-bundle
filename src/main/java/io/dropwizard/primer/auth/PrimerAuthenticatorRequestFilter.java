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

import com.codahale.metrics.annotation.Metered;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.InvalidSignatureException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.MalformedJsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.TokenExpiredException;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Strings;
import feign.FeignException;
import io.dropwizard.primer.cache.TokenCacheManager;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.joda.time.Interval;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import static com.google.common.base.Optional.fromNullable;


/**
 * @author phaneesh
 */
@Slf4j
@Provider
@Priority(Priorities.AUTHENTICATION)
public class PrimerAuthenticatorRequestFilter implements ContainerRequestFilter {


    private JsonWebTokenParser tokenParser;

    private HmacSHA512Verifier verifier;

    private PrimerBundleConfiguration configuration;

    private final Duration acceptableClockSkew;

    private ObjectMapper objectMapper;

    private static final String AUTHORIZED_FOR_ID = "X-AUTHORIZED-FOR-ID";
    private static final String AUTHORIZED_FOR_SUBJECT = "X-AUTHORIZED-FOR-SUBJECT";
    private static final String AUTHORIZED_FOR_NAME = "X-AUTHORIZED-FOR-NAME";

    @Builder
    public PrimerAuthenticatorRequestFilter(final JsonWebTokenParser tokenParser,
                                            final HmacSHA512Verifier verifier,
                                            final PrimerBundleConfiguration configuration, final ObjectMapper objectMapper) {
        this.tokenParser = tokenParser;
        this.verifier = verifier;
        this.configuration = configuration;
        this.acceptableClockSkew = new Duration(configuration.getClockSkew());
        this.objectMapper = objectMapper;
    }

    @Override
    @Metered(name = "primer")
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if(!configuration.isEnabled()) {
            return;
        }
        //Short circuit for all white listed urls
        if(PrimerAuthorizationRegistry.isWhilisted(requestContext.getUriInfo().getPath())) {
            return;
        }
        Optional<String> token = getToken(requestContext);
        if(!token.isPresent()) {
            requestContext.abortWith(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR000").message("Bad request")
                                    .build())).build()
            );
        } else {
            try {
                if(TokenCacheManager.checkBlackList(token.get())) {
                    requestContext.abortWith(
                            Response.status(Response.Status.FORBIDDEN)
                                    .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR001").message("Forbidden")
                                            .build())).build()
                    );
                    return;
                }
                if(TokenCacheManager.checkCache(token.get())) {
                    final JsonWebToken cachedToken = tokenParser.parse(token.get());
                    //Stamp authorization headers for downstream services which can
                    // use this to stop token forgery & misuse
                    stampHeaders(requestContext, cachedToken);
                    //Short circuit for optimization
                    return;
                }
            } catch (ExecutionException e) {
                //Ignore execution execution because of rejection
                log.warn("Error getting token from cache: {}", e.getMessage());
            }
            try {
                JsonWebToken webToken = verifyToken(token.get());
                checkExpiry(webToken);
                boolean isAuthorized = authorize(requestContext, webToken, token.get());
                if(!isAuthorized) {
                    requestContext.abortWith(
                            Response.status(Response.Status.UNAUTHORIZED)
                                    .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR002").message("Unauthorized")
                                            .build())).build()
                    );
                }
                //Stamp authorization headers for downstream services which can use this to stop token forgery & misuse
                stampHeaders(requestContext, webToken);
            } catch (TokenExpiredException e) {
                log.error("Token Expiry Error: {}", e.getMessage());
                requestContext.abortWith(
                        Response.status(Response.Status.PRECONDITION_FAILED)
                                .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR003").message("Expired")
                                        .build())).build()
                );
            } catch (MalformedJsonWebTokenException e) {
                log.error("Token Malformed Error: {}", e.getMessage());
                requestContext.abortWith(
                        Response.status(Response.Status.UNAUTHORIZED)
                                .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR002").message("Unauthorized")
                                        .build())).build()
                );
            } catch (InvalidSignatureException e) {
                log.error("Token Signature Error: {}", e.getMessage());
                requestContext.abortWith(
                        Response.status(Response.Status.UNAUTHORIZED)
                                .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR002").message("Unauthorized")
                                        .build())).build()
                );
            } catch (FeignException e) {
                log.error("Feign error: {}", e.getMessage());
                handleError(Response.Status.fromStatusCode(e.status()), "PR000", e.getMessage(),
                        requestContext, token.get());
            } catch (PrimerException e) {
                log.error("Primer error: {}", e.getMessage());
                handleError(Response.Status.fromStatusCode(e.getStatus()), e.getErrorCode(), e.getMessage(),
                        requestContext, token.get());
            } catch (Exception e) {
                log.error("General error: {}", e.getMessage());
                handleError(Response.Status.INTERNAL_SERVER_ERROR, "PR000", "Error", requestContext, token.get());
            }
        }
    }

    private boolean authorize(ContainerRequestContext requestContext, JsonWebToken webToken, String token) throws PrimerException {
        return PrimerAuthorizationRegistry.authorize(requestContext.getUriInfo().getPath(),
                (String)webToken.claim().getParameter("role"), requestContext.getMethod(), token, webToken);
    }

    private Optional<String> getToken(ContainerRequestContext requestContext) {
        final String header = requestContext.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.debug("Authorization Header: {}", header);
        if (header != null) {
            final String rawToken = header.replaceAll(configuration.getPrefix(), "").trim();
            if(Strings.isNullOrEmpty(rawToken)) {
                return Optional.empty();
            }
            return Optional.of(rawToken);
        }
        return Optional.empty();
    }

    private JsonWebToken verifyToken(String rawToken) {
        final JsonWebToken token = tokenParser.parse(rawToken);
        verifier.verifySignature(token);
        return token;
    }

    private void checkExpiry(JsonWebToken token) {
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

    private boolean inInterval(Instant start, Instant end, Instant now) {
        final Interval interval = new Interval(start, end);
        final Interval currentTimeWithSkew = new Interval(now.minus(acceptableClockSkew), now.plus(acceptableClockSkew));
        return interval.overlaps(currentTimeWithSkew);
    }

    private Instant toInstant(Long input) {
        if (input == null) {
            return null;
        }
        return new Instant(input * 1000);
    }

    private void stampHeaders(ContainerRequestContext requestContext, JsonWebToken webToken) {
        final String tokenType = (String)webToken.claim().getParameter("type");
        switch(tokenType) {
            case "dynamic":
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_ID, (String)webToken.claim().getParameter("user_id"));
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_SUBJECT, webToken.claim().subject());
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_NAME, (String)webToken.claim().getParameter("name"));
                break;
            case "static":
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_SUBJECT, webToken.claim().subject());
                break;
            default:
                log.warn("No auth header stamped for type: {}", tokenType);
        }
    }

    private void handleError(Response.Status status, String errorCode, String message, ContainerRequestContext requestContext,
                             String token) throws JsonProcessingException {
        switch(status) {
            case NOT_FOUND:
                requestContext.abortWith(
                        Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                                .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR002").message("Unauthorized")
                                        .build())).build());
                break;
            case FORBIDDEN:
            case UNAUTHORIZED:
                TokenCacheManager.blackList(token);
                requestContext.abortWith(
                        Response.status(status)
                                .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode(errorCode).message(message).build()))
                                .build());
                break;
            default:
                requestContext.abortWith(
                        Response.status(status)
                                .entity(objectMapper.writeValueAsBytes(
                                        PrimerError.builder().errorCode(errorCode).message(message).build()))
                                .build());
        }
    }
}
