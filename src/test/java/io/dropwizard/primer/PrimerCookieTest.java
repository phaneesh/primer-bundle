package io.dropwizard.primer;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.common.collect.ImmutableMap;
import io.dropwizard.primer.auth.AuthFilter;
import io.dropwizard.primer.auth.filter.PrimerAuthConfigFilter;
import io.dropwizard.primer.model.PrimerConfigurationHolder;
import io.dropwizard.primer.model.PrimerCookie;
import io.dropwizard.primer.util.AesUtils;
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
    private AuthFilter authFilter;

    @Before
    public void setup() throws Exception {
        super.setup();
        primerBundleConfiguration.setCookiesEnabled(true);
        primerBundleConfiguration.setCookiesConfigs(ImmutableMap.of("oculus",
                PrimerCookie.builder().authCookie("OCULUS_G_TOKEN").encryptionKey("1234").build()));
        // init auth filter..
        PrimerConfigurationHolder configurationHolder = new PrimerConfigurationHolder(primerBundleConfiguration);
        authFilter = new PrimerAuthConfigFilter(configurationHolder, mapper, null, null);
    }

    @Test
    public void testForValidCookie() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", "OCULUS_G_TOKEN");
        Optional<String> encryptedToken = authFilter.getToken(requestContext);
        Assert.assertEquals(encryptedToken.get(),token);
    }

    @Test
    public void testForInValidCookie() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", "SCP_G_TOKEN");
        Optional<String> encryptedToken = authFilter.getToken(requestContext);
        Assert.assertEquals(encryptedToken, Optional.empty());
    }

    @Test
    public void testForAuthHeader() {
        // set cookiesEnabled = false to read token from Header
        primerBundleConfiguration.setCookiesEnabled(false);
        ContainerRequest requestContext = containerRequestWithAuthHeader("/apis/test/user");
        Optional<String> encryptedToken = authFilter.getToken(requestContext);
        Assert.assertEquals(encryptedToken.get(),token);
    }

    private ContainerRequest containerRequestWithAuthCookie(String url, String cookie) {
        URI uri = UriBuilder.fromPath(url).build();
        ContainerRequest requestContext = new ContainerRequest(null, uri, "POST",
                null, new MapPropertiesDelegate());
        PrimerCookie oculusCookieConfig = primerBundleConfiguration.getCookiesConfigs().get("oculus");
        String cookieString = String.format("%s=%s; %s", cookie,
                AesUtils.encrypt(oculusCookieConfig.getEncryptionKey(), token), "SameSite=None");
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
