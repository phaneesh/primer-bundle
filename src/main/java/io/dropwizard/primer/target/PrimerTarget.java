package io.dropwizard.primer.target;

import com.fasterxml.jackson.databind.ObjectMapper;
import feign.Target;
import feign.ranger.RangerTarget;
import io.dropwizard.primer.client.PrimerClient;
import io.dropwizard.primer.model.PrimerEndpoint;
import io.dropwizard.primer.model.PrimerRangerEndpoint;
import io.dropwizard.primer.model.PrimerSimpleEndpoint;
import com.google.common.base.Strings;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.curator.framework.CuratorFramework;

import java.util.function.Supplier;

@Slf4j
public class PrimerTarget {

    @Getter
    private final Target<PrimerClient> target;

    @Builder
    public PrimerTarget(PrimerEndpoint primerEndpoint, ObjectMapper objectMapper, Supplier<CuratorFramework> curatorFrameworkSupplier) throws Exception {
        if (primerEndpoint instanceof PrimerSimpleEndpoint) {
            this.target = makeTarget((PrimerSimpleEndpoint) primerEndpoint);
        } else if (primerEndpoint instanceof PrimerRangerEndpoint) {
            this.target = makeTarget((PrimerRangerEndpoint) primerEndpoint, objectMapper, curatorFrameworkSupplier.get());
        } else {
            throw new IllegalArgumentException("unknown primer target type specified");
        }
    }

    private Target<PrimerClient> makeTarget(PrimerSimpleEndpoint primerSimpleEndpoint) {
        String rootPathPrefix = "";
        if (!Strings.isNullOrEmpty(primerSimpleEndpoint.getRootPathPrefix())) {
            rootPathPrefix = "/" + primerSimpleEndpoint.getRootPathPrefix();
        }

        String httpScheme = "http";
        if (primerSimpleEndpoint.isSecure()) {
            httpScheme = "https";
        }
        String url = String.format("%s://%s:%d%s", httpScheme, primerSimpleEndpoint.getHost(), primerSimpleEndpoint.getPort(),
                rootPathPrefix);
        return new Target.HardCodedTarget<>(PrimerClient.class, url);
    }

    private Target<PrimerClient> makeTarget(PrimerRangerEndpoint primerRangerEndpoint,
                                            ObjectMapper objectMapper,
                                            CuratorFramework curatorFramework) throws Exception {
        return RangerTarget.<PrimerClient>builder().type(PrimerClient.class)
                .environment(primerRangerEndpoint.getEnvironment())
                .namespace(primerRangerEndpoint.getNamespace())
                .service(primerRangerEndpoint.getService())
                .curator(curatorFramework)
                .secured(primerRangerEndpoint.isSecure())
                .objectMapper(objectMapper)
                .rootPathPrefix(primerRangerEndpoint.getRootPathPrefix())
                .build();
    }
}
