package io.dropwizard.primer;

import feign.Target;
import io.dropwizard.primer.client.PrimerClient;
import io.dropwizard.primer.model.PrimerSimpleEndpoint;
import io.dropwizard.primer.target.PrimerTarget;
import org.junit.Assert;
import org.junit.Test;

public class PrimerSimpleTargetTest {

    @Test
    public void testSimpleClient() throws Exception {
        PrimerSimpleEndpoint primerSimpleEndpoint = PrimerSimpleEndpoint.builder().host("127.0.0.1").port(80).type("simple").build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerSimpleEndpoint).build().getTarget();
        Assert.assertEquals("http://127.0.0.1:80", primerClientTarget.url());
    }

    @Test
    public void testSimpleClientSecured() throws Exception {
        PrimerSimpleEndpoint primerSimpleEndpoint = PrimerSimpleEndpoint.builder().host("127.0.0.1").type("simple").port(443).secure(true).build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerSimpleEndpoint).build().getTarget();
        Assert.assertEquals("https://127.0.0.1:443", primerClientTarget.url());
    }

    @Test
    public void testSimpleClientDefaultPort() throws Exception {
        PrimerSimpleEndpoint primerSimpleEndpoint = PrimerSimpleEndpoint.builder().host("127.0.0.1").type("simple").build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerSimpleEndpoint).build().getTarget();
        Assert.assertEquals("http://127.0.0.1:80", primerClientTarget.url());
    }

    @Test
    public void testSimpleClientSecuredDefaultPort() throws Exception {
        PrimerSimpleEndpoint primerSimpleEndpoint = PrimerSimpleEndpoint.builder().host("127.0.0.1").type("simple").secure(true).build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerSimpleEndpoint).build().getTarget();
        Assert.assertEquals("https://127.0.0.1:443", primerClientTarget.url());
    }

    @Test
    public void testSimpleClientRootPathPrefix() throws Exception {
        PrimerSimpleEndpoint primerSimpleEndpoint = PrimerSimpleEndpoint.builder().host("127.0.0.1").type("simple").rootPathPrefix("apis/ks").build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerSimpleEndpoint).build().getTarget();
        Assert.assertEquals("http://127.0.0.1:80/apis/ks", primerClientTarget.url());
    }

    @Test
    public void testSimpleClientSecuredRootPathPrefix() throws Exception {
        PrimerSimpleEndpoint primerSimpleEndpoint = PrimerSimpleEndpoint.builder().host("127.0.0.1").type("simple").secure(true).rootPathPrefix("apis/ks").build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerSimpleEndpoint).build().getTarget();
        Assert.assertEquals("https://127.0.0.1:443/apis/ks", primerClientTarget.url());
    }
}
