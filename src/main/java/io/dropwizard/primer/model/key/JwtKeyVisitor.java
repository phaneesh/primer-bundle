package io.dropwizard.primer.model.key;

/***
 Created by mudit.g on May, 2021
 ***/
public interface JwtKeyVisitor<T> {

    T visit(HmacKey hmacKey);

    T visit(RsaJwkKey rsaJwkKey);
}