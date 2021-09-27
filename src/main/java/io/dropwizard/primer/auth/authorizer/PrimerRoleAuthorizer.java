package io.dropwizard.primer.auth.authorizer;

import io.dropwizard.primer.auth.annotation.Authorize;
import io.dropwizard.primer.exception.PrimerException;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwt.JwtClaims;

import javax.ws.rs.container.ContainerRequestContext;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Created by pavan.kumar on 2019-02-20
 *
 * Example authorizer class for role based authorization.
 * Annotation Usage: @Authorize(value = {"roleName"})
 *
 */
@Slf4j
@Builder
public class PrimerRoleAuthorizer implements PrimerAnnotationAuthorizer {

    @Override
    public void authorize(JwtClaims jwtClaims, ContainerRequestContext containerRequestContext, Authorize authorize) throws PrimerException {

        List<String> authorizedRoles = Arrays.asList(authorize.value());

        if (authorizedRoles.contains(jwtClaims.getClaimValueAsString("role")))
            return;

        if(jwtClaims.getClaimValue("roles") != null &&
                !Collections.disjoint(authorizedRoles, (List) jwtClaims.getClaimValue("roles")))
            return;

        throw PrimerException.builder()
                .status(401)
                .errorCode("PR004")
                .message("Unauthorized")
                .recoverable(true)
                .build();
    }
}
