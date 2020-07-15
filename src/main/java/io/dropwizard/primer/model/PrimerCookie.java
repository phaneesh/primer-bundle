package io.dropwizard.primer.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * @author Sudhir
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PrimerCookie {

    String defaultAuthCookie;

    Map<String, String> namespaceAuthCookies;
}
