package io.dropwizard.primer;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.common.collect.ImmutableMap;
import io.dropwizard.primer.auth.AuthFilter;
import io.dropwizard.primer.auth.filter.PrimerAuthConfigFilter;
import io.dropwizard.primer.model.PrimerConfigurationHolder;
import org.glassfish.jersey.server.ContainerRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.util.Optional;

import static io.dropwizard.primer.TestUtils.containerRequestWithAuthCookie;
import static io.dropwizard.primer.TestUtils.containerRequestWithAuthHeader;

/**
 * Token provider & cookies related test cases
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
        primerBundleConfiguration.setCookie(primerCookie);
        // init auth filter..
        PrimerConfigurationHolder configurationHolder = new PrimerConfigurationHolder(primerBundleConfiguration);
        // filter with default token provider with primer bundle
        authFilterWithDefaultProvider = new PrimerAuthConfigFilter(configurationHolder, mapper, null, null,
                bundle.getPrimerTokenProvider());
        // filter with custom token provider
        authFilterWithCustomTokenProvider = new PrimerAuthConfigFilter(configurationHolder, mapper, null, null,
                TestUtils.getCustomTokenProvider(primerCookie, ImmutableMap.of("oculus","OCULUS_G_TOKEN", "scp", "SCP_G_TOKEN")));
    }

    /**
     * Token fetch success
     * Default provider 
     * Pick token from primer cookie[default cookie]
     */
    @Test
    public void testForValidCookie() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", primerCookie, token);
        Optional<String> encryptedToken = authFilterWithDefaultProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken.get(),token);
    }

    /**
     * Fail to fetch token 
     * Default provider 
     * Pick token from primer cookie[default cookie]
     */
    @Test
    public void testForInValidCookie() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", "SCP_G_TOKEN", token);
        Optional<String> encryptedToken = authFilterWithDefaultProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken, Optional.empty());
    }

    /**
     * Token fetch success
     * Custom Token Provider 
     * Pick token from custom implementation based on service name/url pattern 
     */
    @Test
    public void testForValidCookieWithCustomProvider() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", "OCULUS_G_TOKEN", token);
        Optional<String> encryptedToken = authFilterWithCustomTokenProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken.get(),token);
    }

    /**
     * Fail to fetch token 
     * Custom Token Provider 
     * Pick token from custom implementation based on service name/url pattern however different cookie being suppiled
     */
    @Test
    public void testForInValidCookieCustomProvider() {
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", primerCookie, token);
        Optional<String> encryptedToken = authFilterWithCustomTokenProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken, Optional.empty());
    }

    /**
     * Fail to fetch token if cookies is disabled
     * Default Token Provider 
     */
    @Test
    public void testForCookieDisabledFlow() {
        primerBundleConfiguration.setCookiesEnabled(false);
        ContainerRequest requestContext = containerRequestWithAuthCookie("/apis/oculus/user", primerCookie, token);
        Optional<String> encryptedToken = authFilterWithDefaultProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken, Optional.empty());
    }

    /**
     * Success case if AUTHORIZATION headers is present
     * Cookie will be ignored
     * Default Token Provider 
     */
    @Test
    public void testForAuthHeader() {
        ContainerRequest requestContext = containerRequestWithAuthHeader("/apis/test/user", token);
        Optional<String> encryptedToken = authFilterWithDefaultProvider.getToken(requestContext);
        Assert.assertEquals(encryptedToken.get(),token);
    }


}
