package io.dropwizard.primer.auth.authorizer;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import io.dropwizard.primer.auth.annotation.PrimerAuth;

import javax.ws.rs.container.ContainerRequestContext;

public interface PrimerAnnotationAuthorizer {

    boolean authorize(JsonWebToken jwt, ContainerRequestContext containerRequestContext, PrimerAuth primerAuth);
}
