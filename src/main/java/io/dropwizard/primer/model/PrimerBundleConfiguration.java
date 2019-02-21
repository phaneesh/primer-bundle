package io.dropwizard.primer.model;

import com.google.common.collect.ImmutableMap;
import io.dropwizard.primer.auth.AuthType;
import lombok.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author phaneesh
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PrimerBundleConfiguration {

    @Valid
    private PrimerEndpoint endpoint;

    private int cacheExpiry;

    private int cacheMaxSize;

    private int clockSkew;

    private String prefix;

    private String privateKey;

    private boolean enabled = true;

    private Map<AuthType, Boolean> authTypesEnabled = ImmutableMap.of(AuthType.CONFIG, true, AuthType.ANNOTATION, false);

    @Singular("whiteList")
    private Set<String> whileListUrl = new HashSet<>();

    private PrimerAuthorizationMatrix authorizations;
}
