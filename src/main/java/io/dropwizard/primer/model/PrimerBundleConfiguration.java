package io.dropwizard.primer.model;

import lombok.*;

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

    private String host;

    private int port;

    private int cacheExpiry;

    private int cacheMaxSize;

    private int clockSkew;

    private String prefix;

    private String privateKey;

    @Singular("whiteList")
    private Set<String> whileListUrl = new HashSet<>();
}
