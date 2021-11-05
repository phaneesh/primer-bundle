package io.dropwizard.primer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flipkart.ranger.ServiceProviderBuilders;
import com.flipkart.ranger.healthcheck.Healthcheck;
import com.flipkart.ranger.healthcheck.HealthcheckStatus;
import com.flipkart.ranger.serviceprovider.ServiceProvider;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.common.collect.Lists;
import feign.*;
import feign.ranger.common.ShardInfo;
import io.dropwizard.primer.client.PrimerClient;
import io.dropwizard.primer.model.PrimerRangerEndpoint;
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

    private final ObjectMapper objectMapper = new ObjectMapper();

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

    @Test
    public void testHttpPrimerClient() throws Exception {
        PrimerRangerEndpoint primerRangerEndpoint = PrimerRangerEndpoint.builder().type("ranger").environment("test").namespace("test").service("test").build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerRangerEndpoint).objectMapper(objectMapper).curatorFrameworkSupplier(()->curator).build().getTarget();
        assertEquals("http://127.0.0.1:9999", primerClientTarget.url());
    }

    @Test
    public void testHttpsPrimerClient() throws Exception {
        PrimerRangerEndpoint primerRangerEndpoint = PrimerRangerEndpoint.builder().type("ranger").environment("test").namespace("test").service("test").secure(true).build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerRangerEndpoint).objectMapper(objectMapper).curatorFrameworkSupplier(()->curator).build().getTarget();
        assertEquals("https://127.0.0.1:9999", primerClientTarget.url());
    }

    @Test
    public void testHttpPrimerClientWithRootPathPrefix() throws Exception {
        PrimerRangerEndpoint primerRangerEndpoint = PrimerRangerEndpoint.builder().type("ranger").environment("test").namespace("test").service("test").rootPathPrefix("apis/ks").build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerRangerEndpoint).objectMapper(objectMapper).curatorFrameworkSupplier(()->curator).build().getTarget();
        assertEquals("http://127.0.0.1:9999/apis/ks", primerClientTarget.url());
    }

    @Test
    public void testHttpsPrimerClientWithRootPathPrefix() throws Exception {
        PrimerRangerEndpoint primerRangerEndpoint = PrimerRangerEndpoint.builder().type("ranger").environment("test").namespace("test").service("test").secure(true).rootPathPrefix("apis/ks").build();
        Target<PrimerClient> primerClientTarget = PrimerTarget.builder().primerEndpoint(primerRangerEndpoint).objectMapper(objectMapper).curatorFrameworkSupplier(()->curator).build().getTarget();
        assertEquals("https://127.0.0.1:9999/apis/ks", primerClientTarget.url());
    }
}
