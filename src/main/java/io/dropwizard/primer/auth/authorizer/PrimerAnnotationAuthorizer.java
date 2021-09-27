package io.dropwizard.primer.auth.authorizer;

import io.dropwizard.primer.auth.annotation.Authorize;
import io.dropwizard.primer.exception.PrimerException;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import javax.ws.rs.container.ContainerRequestContext;

public interface PrimerAnnotationAuthorizer {

    void authorize(JwtClaims jwtClaims, ContainerRequestContext containerRequestContext, Authorize authorize) throws PrimerException, MalformedClaimException;
}
