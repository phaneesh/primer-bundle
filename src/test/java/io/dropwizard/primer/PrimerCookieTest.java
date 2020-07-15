package io.dropwizard.primer;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.common.collect.ImmutableMap;
import io.dropwizard.primer.auth.AuthFilter;
import io.dropwizard.primer.auth.filter.PrimerAuthConfigFilter;
import io.dropwizard.primer.model.PrimerConfigurationHolder;
import io.dropwizard.primer.model.PrimerCookie;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.ContainerRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.Optional;

/**
 * @author Sudhir
 */
public class PrimerCookieTest extends BaseTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(9999);
    private AuthFilter authFilterWithDefaultProvider;
    private AuthFilter authFilterWithCustomTokenProvider;

    @Before
    public void setup() throws Exception {
        super.setup();
        primerBundleConfiguration.setCookiesEnabled(true);
        primerBundleConfiguration.setPrimerCookie(
                PrimerCookie.builder().defaultAuthCookie("PRIMER_COOKIES")
                        .namespaceAuthCookies(
                                ImmutableMap.of("oculus","OCULUS_G_TOKEN", "scp", "SCP_G_TOKEN")
                        ).build());
        // init auth filter..
        PrimerConfigurationHolder configurationHolder = new PrimerConfigurationHolder(primerBundleConfiguration);
        authFilterWithDefaultProvider = new PrimerAuthConfigFilter(configurationHolder, mapper, null, null,
                bundle.getPrimerTokenProvider());
        authFilterWithCustomTokenProvider = new PrimerAuthConfigFilter(configurationHolder, mapper, null, null,
                TestUtils.getCustomTokenProvider());
    }

    @Test
    public void testForValidCookie() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", "PRIMER_COOKIES");
        Optional<String> encryptedToken = authFilterWithDefaultProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken.get(),token);
    }

    @Test
    public void testForInValidCookie() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", "SCP_G_TOKEN");
        Optional<String> encryptedToken = authFilterWithDefaultProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken, Optional.empty());
    }


    @Test
    public void testForValidCookieWithCustomProvider() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", "OCULUS_G_TOKEN");
        Optional<String> encryptedToken = authFilterWithCustomTokenProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken.get(),token);
    }

    @Test
    public void testForInValidCookieCustomProvider() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", "PRIMER_COOKIES");
        Optional<String> encryptedToken = authFilterWithCustomTokenProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken, Optional.empty());
    }

    @Test
    public void testForCookieDisabledFlow() {
        primerBundleConfiguration.setCookiesEnabled(false);
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", "PRIMER_COOKIES");
        Optional<String> encryptedToken = authFilterWithDefaultProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken, Optional.empty());
    }

    @Test
    public void testForAuthHeader() {
        ContainerRequest requestContext = containerRequestWithAuthHeader("/apis/test/user");
        Optional<String> encryptedToken = authFilterWithDefaultProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken.get(),token);
    }

    private ContainerRequest containerRequestWithAuthCookie(String url, String cookie) {
        URI uri = UriBuilder.fromPath(url).build();
        ContainerRequest requestContext = new ContainerRequest(null, uri, "POST",
                null, new MapPropertiesDelegate());
        String cookieString = String.format("%s=%s; %s", cookie,
                token, "SameSite=None");
        requestContext.getRequestHeaders().add("Cookie", cookieString);
        return requestContext;
    }

    private ContainerRequest containerRequestWithAuthHeader(String url) {
        URI uri = UriBuilder.fromPath(url).build();
        ContainerRequest requestContext = new ContainerRequest(null, uri, "POST",
                null, new MapPropertiesDelegate());
        requestContext.getRequestHeaders().add(HttpHeaders.AUTHORIZATION, token);
        return requestContext;
    }

}
