package io.dropwizard.primer.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.InvalidSignatureException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.MalformedJsonWebTokenException;
import com.github.toastshaman.dropwizard.auth.jwt.exceptions.TokenExpiredException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Strings;
import feign.FeignException;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import io.dropwizard.primer.model.PrimerConfigurationHolder;
import lombok.extern.slf4j.Slf4j;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

/**
 * Created by pavan.kumar on 2019-02-19
 */
@Slf4j
public abstract class AuthFilter implements ContainerRequestFilter {

    protected final AuthType authType;
    protected final PrimerConfigurationHolder configHolder;
    protected final ObjectMapper objectMapper;

    private static final String AUTHORIZED_FOR_ID = "X-AUTHORIZED-FOR-ID";
    private static final String AUTHORIZED_FOR_SUBJECT = "X-AUTHORIZED-FOR-SUBJECT";
    private static final String AUTHORIZED_FOR_NAME = "X-AUTHORIZED-FOR-NAME";
    private static final String AUTHORIZED_FOR_ROLE = "X-AUTHORIZED-FOR-ROLE";

    protected AuthFilter(AuthType authType, PrimerConfigurationHolder configHolder, ObjectMapper objectMapper) {
        this.authType = authType;
        this.configHolder = configHolder;
        this.objectMapper = objectMapper;
    }

    protected JsonWebToken authorize(ContainerRequestContext requestContext, String token, AuthType authType) throws ExecutionException {
        return PrimerAuthorizationRegistry.authorize(requestContext.getUriInfo().getPath(), requestContext.getMethod(), token, authType);
    }

    protected Optional<String> getToken(ContainerRequestContext requestContext) {
        final String header = requestContext.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.debug("Authorization Header: {}", header);
        if (header != null) {
            final String rawToken = header.replaceAll(configHolder.getConfig().getPrefix(), "").trim();
            if (Strings.isNullOrEmpty(rawToken)) {
                return Optional.empty();
            }
            return Optional.of(rawToken);
        }
        return Optional.empty();
    }


    protected void stampHeaders(ContainerRequestContext requestContext, JsonWebToken webToken) {
        final String tokenType = (String) webToken.claim().getParameter("type");
        switch (tokenType) {
            case "dynamic":
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_ID, (String) webToken.claim().getParameter("user_id"));
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_SUBJECT, webToken.claim().subject());
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_NAME, (String) webToken.claim().getParameter("name"));
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_ROLE, (String) webToken.claim().getParameter("role"));
                break;
            case "static":
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_SUBJECT, webToken.claim().subject());
                requestContext.getHeaders().putSingle(AUTHORIZED_FOR_ROLE, (String) webToken.claim().getParameter("role"));
                break;
            default:
                log.warn("No auth header stamped for type: {}", tokenType);
        }
    }

    protected void handleException(Throwable e, ContainerRequestContext requestContext, String token) throws JsonProcessingException {
        if (e.getCause() instanceof TokenExpiredException || e instanceof TokenExpiredException) {
            log.error("Token Expiry Error: {}", e.getMessage());
            abortRequest(
                    requestContext,
                    Response.Status.PRECONDITION_FAILED,
                    PrimerError.builder().errorCode("PR003").message("Expired").build()
            );
        } else if (e.getCause() instanceof MalformedJsonWebTokenException || e instanceof MalformedJsonWebTokenException) {
            log.error("Token Malformed Error: {}", e.getMessage());
            abortRequest(
                    requestContext,
                    Response.Status.UNAUTHORIZED,
                    PrimerError.builder().errorCode("PR004").message("Unauthorized").build()
            );
        } else if (e.getCause() instanceof InvalidSignatureException || e instanceof InvalidSignatureException) {
            log.error("Token Signature Error: {}", e.getMessage());
            abortRequest(
                    requestContext,
                    Response.Status.UNAUTHORIZED,
                    PrimerError.builder().errorCode("PR004").message("Unauthorized").build()
            );
        } else if (e.getCause() instanceof FeignException) {
            log.error("Feign error: {}", e.getMessage());
            handleError(Response.Status.fromStatusCode(((FeignException) e.getCause()).status()), "PR000", e.getCause().getMessage(), token, false,
                    requestContext);

        } else if (e instanceof FeignException) {
            log.error("Feign error: {}", e.getMessage());
            handleError(Response.Status.fromStatusCode(((FeignException) e).status()), "PR000", e.getMessage(), token, false,
                    requestContext);
        } else if (e.getCause() instanceof PrimerException) {
            PrimerException primerException = (PrimerException) e.getCause();
            log.error("Primer error: {}", e.getMessage());
            log.debug("Primer error: {} status: {} errorCode: {} message: {} headers: {}", e.getMessage(),
                    primerException.getStatus(),
                    primerException.getErrorCode(),
                    primerException.getMessage(),
                    requestContext.getHeaders());
            handleError(Response.Status.fromStatusCode(((PrimerException) e.getCause()).getStatus()), ((PrimerException) e.getCause()).getErrorCode(),
                    e.getCause().getMessage(), token, ((PrimerException) e.getCause()).isRecoverable(), requestContext);
        } else if (e instanceof PrimerException) {
            PrimerException primerException = (PrimerException) e;
            log.error("Primer error: {}", e.getMessage());
            log.debug("Primer error: {} status: {} errorCode: {} message: {} headers: {}", e.getMessage(),
                    primerException.getStatus(),
                    primerException.getErrorCode(),
                    primerException.getMessage(),
                    requestContext.getHeaders());
            handleError(Response.Status.fromStatusCode(((PrimerException) e).getStatus()), ((PrimerException) e).getErrorCode(),
                    e.getMessage(), token, ((PrimerException) e).isRecoverable(), requestContext);
        } else {
            log.error("General error: ", e);
            handleError(Response.Status.INTERNAL_SERVER_ERROR, "PR000", "Error", token, false, requestContext);
        }
    }

    protected void handleError(Response.Status status, String errorCode, String message, String token, boolean recoverable,
                             ContainerRequestContext requestContext) throws JsonProcessingException {
        switch (status) {
            case NOT_FOUND:
            case UNAUTHORIZED:
                if (!recoverable)
                    PrimerAuthorizationRegistry.blacklist(token);
                abortRequest(requestContext, Response.Status.UNAUTHORIZED, PrimerError.builder().errorCode("PR004").message("Unauthorized").build());
                break;
            case FORBIDDEN:
                if (!recoverable)
                    PrimerAuthorizationRegistry.blacklist(token);
                abortRequest(requestContext, Response.Status.FORBIDDEN, PrimerError.builder().errorCode("PR002").message("Forbidden").build());
                break;
            default:
                abortRequest(requestContext, status, PrimerError.builder().errorCode(errorCode).message(message).build());
        }
    }

    protected void abortRequest(ContainerRequestContext requestContext, Response.Status status, PrimerError primerError) throws JsonProcessingException {
        requestContext.abortWith(
                Response.status(status.getStatusCode())
                        .entity(objectMapper.writeValueAsBytes(primerError))
                        .build()
        );
    }
}
