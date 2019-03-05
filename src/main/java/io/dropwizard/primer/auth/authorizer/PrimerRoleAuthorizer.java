package io.dropwizard.primer.auth.authorizer;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import io.dropwizard.primer.auth.annotation.Authorize;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import javax.ws.rs.container.ContainerRequestContext;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Created by pavan.kumar on 2019-02-20
 */
@Slf4j
@Builder
public class PrimerRoleAuthorizer implements PrimerAnnotationAuthorizer {

    @Override
    public boolean authorize(JsonWebToken jwt, ContainerRequestContext containerRequestContext, Authorize authorize) {

        List<String> authorizedRoles = Arrays.asList(authorize.value());

        if (authorizedRoles.contains(jwt.claim().getParameter("role")))
            return true;

        return jwt.claim().getParameter("roles") != null &&
                !Collections.disjoint(authorizedRoles, (List) jwt.claim().getParameter("roles"));
    }
}
