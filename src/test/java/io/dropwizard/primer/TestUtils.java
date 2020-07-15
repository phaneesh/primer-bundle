package io.dropwizard.primer;

import io.dropwizard.primer.auth.token.PrimerTokenProvider;
import io.dropwizard.primer.model.PrimerConfigurationHolder;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;
import java.util.Objects;
import java.util.Optional;

/**
 * @author Sudhir
 */
public class TestUtils {

    static class CustomTokenProvider extends PrimerTokenProvider {
        @Override
        protected Optional<String> fetchTokenFromCookies(ContainerRequestContext requestContext, PrimerConfigurationHolder configHolder) {
            // if cookies are not allowed to be used
            if (!configHolder.getConfig().isCookiesEnabled()) return Optional.empty();

            String cookieName = configHolder.getConfig().getPrimerCookie().getDefaultAuthCookie();
            String namespace = null;
            final String[] splitPath = requestContext.getUriInfo().getPath().split("/");
            if (splitPath.length < 2) {
                cookieName = configHolder.getConfig().getPrimerCookie().getDefaultAuthCookie();
            } else {
                namespace = splitPath[1];
            }
            cookieName = configHolder.getConfig().getPrimerCookie().getNamespaceAuthCookies()
                    .getOrDefault(namespace, cookieName);
            if (Objects.nonNull(cookieName)) {
                Cookie cookie = requestContext.getCookies().get(cookieName);
                if (Objects.nonNull(cookie)) {
                    final String cookieValue = cookie.getValue();
                    return Optional.ofNullable(cookieValue);
                }
            }
            return Optional.empty();
        }
    }

    static PrimerTokenProvider getCustomTokenProvider(){
        return new CustomTokenProvider();
    }
}
