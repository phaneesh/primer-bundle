package io.dropwizard.primer.model.key;

import lombok.*;

/***
 Created by mudit.g on May, 2021
 ***/
@Data
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class HmacKey extends JwtKey {

    @NonNull
    private String privateKey;

    @Builder
    public HmacKey(String privateKey) {
        super(JwtKeyType.HMAC);
        this.privateKey = privateKey;
    }

    public HmacKey() {
        super(JwtKeyType.HMAC);
    }

    @Override
    public <T> T accept(JwtKeyVisitor<T> visitor) {
        return visitor.visit(this);
    }
}