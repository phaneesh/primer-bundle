package io.dropwizard.primer.auth.token;

import com.google.common.base.Strings;
import io.dropwizard.primer.model.PrimerConfigurationHolder;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import java.util.Objects;
import java.util.Optional;

/**
 * @author Sudhir
 */
@Slf4j
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PrimerTokenProvider {

    String cookie;

    /**
     * Read token from cookies
     * @param requestContext
     * @param configHolder
     * @return
     */
    protected Optional<String> fetchTokenFromCookies(ContainerRequestContext requestContext,
                                                   PrimerConfigurationHolder configHolder){
        // if cookies auth is not allowed
        if (!configHolder.getConfig().isCookiesEnabled()) return Optional.empty();

        if (Objects.nonNull(this.cookie)) {
            Cookie cookie = requestContext.getCookies().get(this.cookie);
            if (Objects.nonNull(cookie)) {
                final String cookieValue = cookie.getValue();
                return Optional.ofNullable(cookieValue);
            }
        }
        return Optional.empty();
    }

    /**
     * Read token from header
     * @param requestContext
     * @param configHolder
     * @return
     */
    protected Optional<String> fetchTokenFromHeader(ContainerRequestContext requestContext,
                                                 PrimerConfigurationHolder configHolder){
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

    /**
     * Read token from supported headers/cookies
     * @param requestContext
     * @param configHolder
     * @return
     */
    public Optional<String> getToken(ContainerRequestContext requestContext,
                                     PrimerConfigurationHolder configHolder) {
        Optional<String> header = fetchTokenFromHeader(requestContext, configHolder);
        if (!header.isPresent())
            // if Authorization header is not present read from cookie
            header = fetchTokenFromCookies(requestContext, configHolder);
        return header;
    }

}
