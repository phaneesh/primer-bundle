package io.dropwizard.primer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.flipkart.ranger.ServiceProviderBuilders;
import com.flipkart.ranger.healthcheck.Healthcheck;
import com.flipkart.ranger.healthcheck.HealthcheckStatus;
import com.flipkart.ranger.serviceprovider.ServiceProvider;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.common.collect.Lists;
import feign.*;
import feign.ranger.common.ShardInfo;
import io.dropwizard.primer.client.PrimerClient;
import io.dropwizard.primer.model.PrimerEndpoint;
import io.dropwizard.primer.target.PrimerTarget;
import lombok.extern.slf4j.Slf4j;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.RetryForever;
import org.apache.curator.test.TestingCluster;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.util.List;
import static org.junit.Assert.*;

@Slf4j
public class PrimerRangerTargetTest {
    private TestingCluster testingCluster;

    private List<Healthcheck> healthchecks = Lists.newArrayList();
    private ServiceProvider<ShardInfo> serviceProvider;

    private CuratorFramework curator;

    private final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());

    private final Logger.ErrorLogger logger = new Logger.ErrorLogger();

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(9999);

    @Before
    public void startTestCluster() throws Exception {

        testingCluster = new TestingCluster(1);
        testingCluster.start();
        curator = CuratorFrameworkFactory.builder()
                .connectString(testingCluster.getConnectString())
                .namespace("test")
                .retryPolicy(new RetryForever(3000))
                .build();
        curator.start();
        serviceProvider = ServiceProviderBuilders.<ShardInfo>shardedServiceProviderBuilder()
                .withCuratorFramework(curator)
                .withNamespace("test")
                .withServiceName("test")
                .withSerializer(data -> {
                    try {
                        return objectMapper.writeValueAsBytes(data);
                    } catch (Exception e) {
                        log.warn("Could not parse node data", e);
                    }
                    return null;
                })
                .withHostname("127.0.0.1")
                .withPort(9999)
                .withNodeData(ShardInfo.builder()
                        .environment("test")
                        .build())
                .withHealthcheck(() -> {
                    for(Healthcheck healthcheck : healthchecks) {
                        if(HealthcheckStatus.unhealthy == healthcheck.check()) {
                            return HealthcheckStatus.unhealthy;
                        }
                    }
                    return HealthcheckStatus.healthy;
                })
                .buildServiceDiscovery();
        serviceProvider.start();
    }

    @After
    public void stopTestCluster() throws Exception {
        if(null != serviceProvider ) {
            serviceProvider.stop();
        }
        if(null != curator) {
            curator.close();
        }
        if(null != testingCluster) {
            testingCluster.close();
        }

    }

    private void check(String extraConfig, String expectedUrl) throws Exception {
        PrimerEndpoint primerEndpoint = objectMapper.readValue(
                "---\n" +
                        "type: ranger\n" +
                        "namespace: test\n" +
                        "service: test\n" +
                        "environment: test\n" +
                        extraConfig, PrimerEndpoint.class);
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerEndpoint).objectMapper(objectMapper).curatorFrameworkSupplier(()->curator).build().getTarget();
        assertEquals(expectedUrl, primerClientTarget.url());
    }

    @Test
    public void testHttpPrimerClient() throws Exception {
        check("", "http://127.0.0.1:9999");
    }

    @Test
    public void testHttpsPrimerClient() throws Exception {
        check("secure: true", "https://127.0.0.1:9999");
    }

    @Test
    public void testHttpPrimerClientWithRootPathPrefix() throws Exception {
        check("rootPathPrefix: apis/ks", "http://127.0.0.1:9999/apis/ks");
    }

    @Test
    public void testHttpsPrimerClientWithRootPathPrefix() throws Exception {
        check("secure: true\n" + "rootPathPrefix: apis/ks", "https://127.0.0.1:9999/apis/ks");
    }
}
