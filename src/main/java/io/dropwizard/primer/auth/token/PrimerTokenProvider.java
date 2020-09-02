package io.dropwizard.primer.auth.token;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Strings;
import io.dropwizard.primer.model.PrimerConfigurationHolder;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import java.util.Objects;
import java.util.Optional;

import static io.dropwizard.primer.auth.AuthConstants.*;

/**
 * @author Sudhir
 */
@Slf4j
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PrimerTokenProvider {

    // default cookie name for primer auth
    protected String primerCookie = "P_SESSIONID";

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

        if (Objects.nonNull(this.primerCookie)) {
            Cookie cookie = requestContext.getCookies().get(this.primerCookie);
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
            // if Authorization header is not present read from primerCookie
            header = fetchTokenFromCookies(requestContext, configHolder);
        return header;
    }

    /**
     *
     * @param requestContext
     * @param webToken
     * @param decryptedToken this string may be used in overriding classes
     */
    public void stampHeaders(ContainerRequestContext requestContext, JsonWebToken webToken, String decryptedToken) {
        final String tokenType = (String) webToken.claim().getParameter("type");
        MultivaluedMap<String, String> headers = requestContext.getHeaders();
        switch (tokenType) {
            case "dynamic":
                headers.putSingle(AUTHORIZED_FOR_ID, (String) webToken.claim().getParameter("user_id"));
                headers.putSingle(AUTHORIZED_FOR_SUBJECT, webToken.claim().subject());
                headers.putSingle(AUTHORIZED_FOR_NAME, (String) webToken.claim().getParameter("name"));
                headers.putSingle(AUTHORIZED_FOR_ROLE, (String) webToken.claim().getParameter("role"));
                break;
            case "static":
                headers.putSingle(AUTHORIZED_FOR_SUBJECT, webToken.claim().subject());
                headers.putSingle(AUTHORIZED_FOR_ROLE, (String) webToken.claim().getParameter("role"));
                break;
            default:
                log.warn("No auth header stamped for type: {}", tokenType);
        }
    }
}
