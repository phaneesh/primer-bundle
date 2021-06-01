package io.dropwizard.primer.model.key;

import lombok.*;

/***
 Created by mudit.g on May, 2021
 ***/
@Data
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class RsaJwkKey extends JwtKey {

    @NonNull
    private String keyId;

    @Builder
    public RsaJwkKey(String keyId) {
        super(JwtKeyType.RSA_JWK);
        this.keyId = keyId;
    }

    public RsaJwkKey() {
        super(JwtKeyType.RSA_JWK);
    }

    @Override
    public <T> T accept(JwtKeyVisitor<T> visitor) {
        return visitor.visit(this);
    }
}