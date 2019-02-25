package io.dropwizard.primer.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.primer.auth.annotation.PrimerAuth;
import io.dropwizard.primer.auth.authorizer.PrimerAnnotationAuthorizer;
import io.dropwizard.primer.auth.filter.PrimerAuthAnnotationFilter;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.Builder;

import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.lang.reflect.Method;
import java.util.stream.Stream;

public class PrimerAuthAnnotationFeature implements DynamicFeature {

    private final PrimerBundleConfiguration configuration;
    private final ObjectMapper mapper;
    private final PrimerAnnotationAuthorizer authorizer;

    @Builder
    public PrimerAuthAnnotationFeature(final PrimerBundleConfiguration configuration, final ObjectMapper mapper, final PrimerAnnotationAuthorizer authorizer) {
        this.configuration = configuration;
        this.mapper = mapper;
        this.authorizer = authorizer;
    }

    public void configure(ResourceInfo resourceInfo, FeatureContext featureContext) {
        final Method resourceMethod = resourceInfo.getResourceMethod();
        if (resourceMethod != null) {
            Stream.of(resourceMethod.getDeclaredAnnotations())
                    .filter(annotation -> annotation.annotationType().equals(PrimerAuth.class))
                    .map(PrimerAuth.class::cast)
                    .findFirst()
                    .ifPresent(primerAuth ->
                            featureContext.register(
                                    PrimerAuthAnnotationFilter.builder()
                                            .configuration(configuration)
                                            .objectMapper(mapper)
                                            .primerAuth(primerAuth)
                                            .authorizer(authorizer)
                                            .build()
                            )
                    );
        }
    }
}