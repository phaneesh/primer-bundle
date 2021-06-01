package io.dropwizard.primer.model.key;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.Data;

/***
 Created by mudit.g on May, 2021
 ***/
@Data
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXISTING_PROPERTY, property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = HmacKey.class, name = "HMAC"),
        @JsonSubTypes.Type(value = RsaJwkKey.class, name = "RSA_JWK"),
})
public abstract class JwtKey {

    protected JwtKeyType type;

    protected JwtKey(JwtKeyType type) {
        this.type = type;
    }

    public abstract <T> T accept(JwtKeyVisitor<T> visitor);
}
