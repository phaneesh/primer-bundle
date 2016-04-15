package io.dropwizard.primer.model;

import lombok.*;

import javax.validation.Valid;
import java.util.HashSet;
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

    @Singular("whiteList")
    private Set<String> whileListUrl = new HashSet<>();
}
