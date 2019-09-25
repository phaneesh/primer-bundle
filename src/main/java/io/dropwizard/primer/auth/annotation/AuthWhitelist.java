package io.dropwizard.primer.auth.annotation;

import io.dropwizard.primer.auth.whitelist.WhitelistType;

import javax.ws.rs.NameBinding;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;

/**
 * Created by pavan.kumar on 2019-09-23
 */
@NameBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({TYPE, METHOD})
public @interface AuthWhitelist {

    WhitelistType type();

    String value();

}
