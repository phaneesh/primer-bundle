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
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.InvalidSignatureException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.MalformedJsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.TokenExpiredException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Strings;
import com.google.common.util.concurrent.UncheckedExecutionException;
import feign.FeignException;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import javax.annotation.Priority;
import javax.inject.Singleton;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;


/**
 * @author phaneesh
 */
@Slf4j
@Provider
@Priority(Priorities.AUTHENTICATION)
@Singleton
public class PrimerAuthenticatorRequestFilter implements ContainerRequestFilter {


    private PrimerBundleConfiguration configuration;

    private ObjectMapper objectMapper;

    private static final String AUTHORIZED_FOR_ID = "X-AUTHORIZED-FOR-ID";
    private static final String AUTHORIZED_FOR_SUBJECT = "X-AUTHORIZED-FOR-SUBJECT";
    private static final String AUTHORIZED_FOR_NAME = "X-AUTHORIZED-FOR-NAME";

    @Builder
    public PrimerAuthenticatorRequestFilter(final PrimerBundleConfiguration configuration, final ObjectMapper objectMapper) {
        this.configuration = configuration;
        this.objectMapper = objectMapper;
    }

    @Override
    @Metered(name = "primer")
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (!configuration.isEnabled()) {
            return;
        }
        //Short circuit for all white listed urls
        if (PrimerAuthorizationRegistry.isWhilisted(requestContext.getUriInfo().getPath())) {
            return;
        }
        Optional<String> token = getToken(requestContext);
        if (!token.isPresent()) {
            requestContext.abortWith(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR000").message("Bad request")
                                    .build())).build()
            );
        } else {
            try {
                JsonWebToken webToken = authorize(requestContext, token.get());
                //Stamp authorization headers for downstream services which can
                // use this to stop token forgery & misuse
                stampHeaders(requestContext, webToken);
            } catch (ExecutionException e) {
                if (e.getCause() instanceof PrimerException) {
                    handleException(e.getCause(), requestContext, token.get());
                } else {
                    handleException(e, requestContext, token.get());
                }
            } catch (UncheckedExecutionException e) {
                if (e.getCause() instanceof CompletionException) {
                    handleException(e.getCause().getCause(), requestContext, token.get());
                } else {
                    handleException(e.getCause(), requestContext, token.get());
                }
            } catch (Exception e) {
                log.error("Execution error: {}", e.getMessage());
                handleError(Response.Status.INTERNAL_SERVER_ERROR, "PR000", "Error", token.get(), requestContext);
            }
        }
    }

    private JsonWebToken authorize(ContainerRequestContext requestContext, String token) throws ExecutionException {
        return PrimerAuthorizationRegistry.authorize(requestContext.getUriInfo().getPath(), requestContext.getMethod(), token);
    }

    private Optional<String> getToken(ContainerRequestContext requestContext) {
        final String header = requestContext.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.debug("Authorization Header: {}", header);
        if (header != null) {
            final String rawToken = header.replaceAll(configuration.getPrefix(), "").trim();
            if (Strings.isNullOrEmpty(rawToken)) {
                return Optional.empty();
            }
            return Optional.of(rawToken);
        }
        return Optional.empty();
    }


    private void stampHeaders(ContainerRequestContext requestContext, JsonWebToken webToken) {
        final String tokenType = (String) webToken.claim().getParameter("type");
        switch (tokenType) {
            case "dynamic":
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_ID, (String) webToken.claim().getParameter("user_id"));
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_SUBJECT, webToken.claim().subject());
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_NAME, (String) webToken.claim().getParameter("name"));
                break;
            case "static":
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_SUBJECT, webToken.claim().subject());
                break;
            default:
                log.warn("No auth header stamped for type: {}", tokenType);
        }
    }

    private void handleException(Throwable e, ContainerRequestContext requestContext, String token) throws JsonProcessingException {
        if (e.getCause() instanceof TokenExpiredException || e instanceof TokenExpiredException) {
            log.error("Token Expiry Error: {}", e.getMessage());
            requestContext.abortWith(
                    Response.status(Response.Status.PRECONDITION_FAILED)
                            .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR003").message("Expired")
                                    .build())).build()
            );
        } else if (e.getCause() instanceof MalformedJsonWebTokenException || e instanceof MalformedJsonWebTokenException) {
            log.error("Token Malformed Error: {}", e.getMessage());
            requestContext.abortWith(
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR004").message("Unauthorized")
                                    .build())).build()
            );
        } else if (e.getCause() instanceof InvalidSignatureException || e instanceof InvalidSignatureException) {
            log.error("Token Signature Error: {}", e.getMessage());
            requestContext.abortWith(
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR004").message("Unauthorized")
                                    .build())).build()
            );
        } else if (e.getCause() instanceof FeignException) {
            log.error("Feign error: {}", e.getMessage());
            handleError(Response.Status.fromStatusCode(((FeignException) e.getCause()).status()), "PR000", e.getCause().getMessage(), token,
                    requestContext);

        } else if (e instanceof FeignException) {
            log.error("Feign error: {}", e.getMessage());
            handleError(Response.Status.fromStatusCode(((FeignException) e).status()), "PR000", e.getMessage(), token,
                    requestContext);
        } else if (e.getCause() instanceof PrimerException) {
            PrimerException primerException = (PrimerException) e.getCause();
            log.error("Primer error: {} status: {} errorCode: {} message: {} headers: {}", e.getMessage(),
                    primerException.getStatus(),
                    primerException.getErrorCode(),
                    primerException.getMessage(),
                    requestContext.getHeaders());
            handleError(Response.Status.fromStatusCode(((PrimerException) e.getCause()).getStatus()), ((PrimerException) e.getCause()).getErrorCode(),
                    e.getCause().getMessage(), token, requestContext);
        } else if (e instanceof PrimerException) {
            PrimerException primerException = (PrimerException) e;
            log.error("Primer error: {} status: {} errorCode: {} message: {} headers: {}", e.getMessage(),
                    primerException.getStatus(),
                    primerException.getErrorCode(),
                    primerException.getMessage(),
                    requestContext.getHeaders());
            handleError(Response.Status.fromStatusCode(((PrimerException) e).getStatus()), ((PrimerException) e).getErrorCode(),
                    e.getMessage(), token, requestContext);
        } else {
            log.error("General error: {}", e);
            handleError(Response.Status.INTERNAL_SERVER_ERROR, "PR000", "Error", token, requestContext);
        }
    }

    private void handleError(Response.Status status, String errorCode, String message, String token,
                             ContainerRequestContext requestContext) throws JsonProcessingException {
        switch (status) {
            case NOT_FOUND:
            case UNAUTHORIZED:
                PrimerAuthorizationRegistry.blacklist(token);
                requestContext.abortWith(
                        Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                                .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR004").message("Unauthorized")
                                        .build())).build());
                break;
            case FORBIDDEN:
                PrimerAuthorizationRegistry.blacklist(token);
                requestContext.abortWith(
                        Response.status(Response.Status.FORBIDDEN.getStatusCode())
                                .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR002").message("Forbidden")
                                        .build())).build());
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
