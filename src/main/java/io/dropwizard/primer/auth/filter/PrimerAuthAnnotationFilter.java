package io.dropwizard.primer.auth.filter;

import com.codahale.metrics.annotation.Metered;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.util.concurrent.UncheckedExecutionException;
import io.dropwizard.primer.auth.AuthFilter;
import io.dropwizard.primer.auth.AuthType;
import io.dropwizard.primer.auth.annotation.Authorize;
import io.dropwizard.primer.auth.authorizer.PrimerAnnotationAuthorizer;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.CompletionException;

/**
 * Created by pavan.kumar on 2019-02-19
 */
@Slf4j
@Provider
@Priority(Priorities.AUTHENTICATION)
public class PrimerAuthAnnotationFilter extends AuthFilter {

    private final PrimerAnnotationAuthorizer authorizer;
    private final Authorize authorize;

    @Builder
    public PrimerAuthAnnotationFilter(PrimerBundleConfiguration configuration, ObjectMapper objectMapper,
                                      Authorize authorize, PrimerAnnotationAuthorizer authorizer) {
        super(AuthType.ANNOTATION, configuration, objectMapper);
        this.authorizer = authorizer;
        this.authorize = authorize;
    }

    @Override
    @Metered(name = "authorize")
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (!configuration.isEnabled() || !configuration.getAuthTypesEnabled().getOrDefault(AuthType.ANNOTATION, false)) {
            return;
        }

        Optional<String> token = getToken(requestContext);
        if (!token.isPresent()) {
            requestContext.abortWith(
                    Response.status(configuration.getAbsentTokenStatus())
                            .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR000").message("Bad request")
                                    .build())).build()
            );
        } else {
            try {
                JsonWebToken webToken = authorize(requestContext, token.get(), this.authType);

                // Execute authorizer
                if (authorizer != null)
                    authorizer.authorize(webToken, requestContext, authorize);

                //Stamp authorization headers for downstream services which can
                // use this to stop token forgery & misuse
                stampHeaders(requestContext, webToken);
            } catch (UncheckedExecutionException e) {
                if (e.getCause() instanceof CompletionException) {
                    handleException(e.getCause().getCause(), requestContext, token.get());
                } else {
                    handleException(e.getCause(), requestContext, token.get());
                }
            } catch (Exception e) {
                if (e.getCause() instanceof PrimerException) {
                    handleException(e.getCause(), requestContext, token.get());
                } else {
                    handleException(e, requestContext, token.get());
                }
            }
        }

    }
}
