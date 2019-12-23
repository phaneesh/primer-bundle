package io.dropwizard.primer.auth.filter;

import com.codahale.metrics.annotation.Metered;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.util.concurrent.UncheckedExecutionException;
import io.dropwizard.primer.auth.AuthFilter;
import io.dropwizard.primer.auth.AuthType;
import io.dropwizard.primer.auth.annotation.AuthWhitelist;
import io.dropwizard.primer.auth.annotation.Authorize;
import io.dropwizard.primer.auth.authorizer.PrimerAnnotationAuthorizer;
import io.dropwizard.primer.auth.whitelist.AuthWhitelistValidator;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import javax.annotation.Priority;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletionException;

/**
 * Created by pavan.kumar on 2019-02-19
 */
@Slf4j
@Provider
@Priority(Priorities.AUTHENTICATION)
@Singleton
public class PrimerAuthAnnotationFilter extends AuthFilter {

    @Context private HttpServletRequest requestProxy;
    @Context private ResourceInfo resourceInfo;

    private final PrimerAnnotationAuthorizer authorizer;

    @Builder
    public PrimerAuthAnnotationFilter(final PrimerBundleConfiguration configuration,
                                      final ObjectMapper objectMapper,
                                      final PrimerAnnotationAuthorizer authorizer) {
        super(AuthType.ANNOTATION, configuration, objectMapper);
        this.authorizer = authorizer;
    }

    @Override
    @Metered(name = "authorize")
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // Do not proceed further with Auth if its disabled or whitelisted
        if (!isEnabled() || isWhitelisted())
            return;

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
                    authorizer.authorize(webToken, requestContext, getAuthorizeAnnotation());

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

    private boolean isEnabled() {
        return configuration.isEnabled()
                && configuration.getAuthTypesEnabled().getOrDefault(AuthType.ANNOTATION, false)
                && Objects.nonNull(getAuthorizeAnnotation());
    }

    private boolean isWhitelisted() {
        // true if whitelisting criteria matches
        AuthWhitelist authWhitelist = resourceInfo.getResourceMethod().getAnnotation(AuthWhitelist.class);
        return Objects.nonNull(authWhitelist)
                && authWhitelist.type().accept(new AuthWhitelistValidator(authWhitelist, requestProxy));
    }

    private Authorize getAuthorizeAnnotation() {
        return resourceInfo.getResourceMethod().getAnnotation(Authorize.class);
    }
}
