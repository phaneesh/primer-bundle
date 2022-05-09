package io.dropwizard.primer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import feign.Target;
import io.dropwizard.primer.client.PrimerClient;
import io.dropwizard.primer.model.PrimerEndpoint;
import io.dropwizard.primer.target.PrimerTarget;
import org.junit.Assert;
import org.junit.Test;

public class PrimerSimpleTargetTest {
    private final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());

    private void check(String extraConfig, String expectedUrl) throws Exception {
        PrimerEndpoint primerEndpoint = objectMapper.readValue(
                "---\n" +
                        "type: simple\n" +
                        "host: 127.0.0.1\n" +
                        extraConfig, PrimerEndpoint.class);

        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerEndpoint).build().getTarget();
        Assert.assertEquals(expectedUrl, primerClientTarget.url());
    }

    @Test
    public void testSimpleClient() throws Exception {
        check("port: 80", "http://127.0.0.1:80");
    }

    @Test
    public void testSimpleClientSecured() throws Exception {
        check("port: 443\n" + "secure: true", "https://127.0.0.1:443");
    }

    @Test
    public void testSimpleClientDefaultPort() throws Exception {
        check("", "http://127.0.0.1:80");
    }

    @Test
    public void testSimpleClientSecuredDefaultPort() throws Exception {
        check("secure: true", "https://127.0.0.1:443");
    }

    @Test
    public void testSimpleClientRootPathPrefix() throws Exception {
        check("rootPathPrefix: apis/ks", "http://127.0.0.1:80/apis/ks");
    }

    @Test
    public void testSimpleClientSecuredRootPathPrefix() throws Exception {
        check("secure: true\n" + "rootPathPrefix: apis/ks", "https://127.0.0.1:443/apis/ks");
    }
}
