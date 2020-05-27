package io.dropwizard.primer.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.NotEmpty;

/**
 * @author Sudhir
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PrimerCookie {
    @NotEmpty
    String authCookie;
    @NotEmpty
    String encryptionKey;
}
