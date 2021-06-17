package io.dropwizard.primer.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import feign.FeignException;
import io.dropwizard.primer.auth.token.PrimerTokenProvider;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerConfigurationHolder;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import java.util.Optional;

/**
 * Created by pavan.kumar on 2019-02-19
 */
@Slf4j
public abstract class AuthFilter implements ContainerRequestFilter {

    protected final AuthType authType;
    protected final PrimerConfigurationHolder configHolder;
    protected final ObjectMapper objectMapper;
    protected final PrimerTokenProvider primerTokenProvider;
    protected final JwtConsumer validationsSkippedJwtConsumer;

    protected AuthFilter(AuthType authType, PrimerConfigurationHolder configHolder, ObjectMapper objectMapper,
                         PrimerTokenProvider primerTokenProvider) {
        this.authType = authType;
        this.configHolder = configHolder;
        this.objectMapper = objectMapper;
        this.primerTokenProvider = primerTokenProvider;
        this.validationsSkippedJwtConsumer = new JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipAllDefaultValidators()
                .build();
    }

    protected JwtClaims authorize(ContainerRequestContext requestContext, String token, AuthType authType) throws InvalidJwtException {
        String primerKeyId = getKeyId(token);
        return PrimerAuthorizationRegistry.authorize(requestContext.getUriInfo().getPath(), requestContext.getMethod(),
                token, authType, primerKeyId);
    }

    public Optional<String> getToken(ContainerRequestContext requestContext) {
        return primerTokenProvider.getToken(requestContext, configHolder);
    }

    protected void handleException(Throwable e, ContainerRequestContext requestContext, String token) throws JsonProcessingException {
        if (e.getCause() instanceof InvalidJwtException || e instanceof InvalidJwtException) {
            InvalidJwtException invalidJwtException = (InvalidJwtException) e;
            if (invalidJwtException.hasExpired()) {
                log.error("Token Expiry Error: {}", e.getMessage());
                abortRequest(
                        requestContext,
                        Response.Status.PRECONDITION_FAILED,
                        PrimerError.builder().errorCode("PR003").message("Expired").build()
                );
            } else if (invalidJwtException.hasErrorCode(ErrorCodes.SIGNATURE_INVALID)) {
                log.error("Token Signature Error: {}", e.getMessage());
                abortRequest(
                        requestContext,
                        Response.Status.UNAUTHORIZED,
                        PrimerError.builder().errorCode("PR004").message("Unauthorized").build()
                );
            } else {
                log.error("Token Malformed Error: {}", e.getMessage());
                abortRequest(
                        requestContext,
                        Response.Status.UNAUTHORIZED,
                        PrimerError.builder().errorCode("PR004").message("Unauthorized").build()
                );
            }
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

    private String getKeyId(String token) throws InvalidJwtException {
        JwtClaims jwtClaims = validationsSkippedJwtConsumer.processToClaims(token);
        return jwtClaims.getClaimValueAsString("key_id");
    }
}
