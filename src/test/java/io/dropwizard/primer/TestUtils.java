package io.dropwizard.primer;

import io.dropwizard.primer.auth.token.PrimerTokenProvider;
import io.dropwizard.primer.model.PrimerConfigurationHolder;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.ContainerRequest;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Test Utility
 * @author Sudhir
 */
class TestUtils {

    /**
     *  Custom PrimerTokenProvider implementation to pick cookie name based on service/url match
     *  Helpful for multiple app auth support based on different cookie
     */
    static class CustomTokenProvider extends PrimerTokenProvider {

        Map<String, String> namespaceCookies;

        CustomTokenProvider(String cookieName, Map<String, String> namespaceCookies) {
            super(cookieName);
            this.namespaceCookies = namespaceCookies;
        }

        @Override
        protected Optional<String> fetchTokenFromCookies(ContainerRequestContext requestContext, PrimerConfigurationHolder configHolder) {
            // if cookies are not allowed to be used
            if (!configHolder.getConfig().isCookiesEnabled()) return Optional.empty();

            String primerCookie = configHolder.getConfig().getCookie();
            String namespace = null;
            final String[] splitPath = requestContext.getUriInfo().getPath().split("/");
            if (splitPath.length >= 2) {
                namespace = splitPath[1];
            }
            primerCookie = namespaceCookies.getOrDefault(namespace, primerCookie);
            if (Objects.nonNull(primerCookie)) {
                Cookie cookie = requestContext.getCookies().get(primerCookie);
                if (Objects.nonNull(cookie)) {
                    final String cookieValue = cookie.getValue();
                    return Optional.ofNullable(cookieValue);
                }
            }
            return Optional.empty();
        }
    }

    /**
     * Util method to return PrimerTokenProvider
     * @param cookieName
     * @param namespaceCookies
     * @return
     */
    static PrimerTokenProvider getCustomTokenProvider(String cookieName, Map<String, String> namespaceCookies){
        return new CustomTokenProvider(cookieName, namespaceCookies);
    }

    /**
     * Utils method for container request with cookies
     * @param url
     * @param cookie
     * @return
     */
    static ContainerRequest containerRequestWithAuthCookie(String url, String cookie, String token) {
        URI uri = UriBuilder.fromPath(url).build();
        ContainerRequest requestContext = new ContainerRequest(null, uri, "POST",
                null, new MapPropertiesDelegate());
        String cookieString = String.format("%s=%s; %s", cookie,
                token, "SameSite=None");
        requestContext.getRequestHeaders().add("Cookie", cookieString);
        return requestContext;
    }

    /**
     * Util method for container request with auth header
     * @param url
     * @return
     */
    static ContainerRequest containerRequestWithAuthHeader(String url, String token) {
        URI uri = UriBuilder.fromPath(url).build();
        ContainerRequest requestContext = new ContainerRequest(null, uri, "POST",
                null, new MapPropertiesDelegate());
        requestContext.getRequestHeaders().add(HttpHeaders.AUTHORIZATION, token);
        return requestContext;
    }
}
