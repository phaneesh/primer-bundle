package io.dropwizard.primer.auth;

import lombok.*;

/**
 * @author phaneesh
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(exclude = {"path", "method"})
@ToString
@Builder
public class TokenKey {

    private String token;

    private String path;

    private String method;
}
