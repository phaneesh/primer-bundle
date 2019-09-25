package io.dropwizard.primer.auth.whitelist;

import io.dropwizard.primer.auth.annotation.AuthWhitelist;
import lombok.Builder;

import java.util.Arrays;

/**
 * Created by pavan.kumar on 2019-09-23
 */
public class AuthWhitelistValidator implements WhitelistType.Visitor<Boolean> {

    private final AuthWhitelist authWhitelist;
    private final String clientIP;

    @Builder
    public AuthWhitelistValidator(AuthWhitelist authWhitelist, String clientIP) {
        this.authWhitelist = authWhitelist;
        this.clientIP = clientIP;
    }

    @Override
    public Boolean visitOptional() {
        return Boolean.valueOf(authWhitelist.value());
    }

    @Override
    public Boolean visitIP() {
        return Arrays
                .asList(authWhitelist.value().split(","))
                .contains(clientIP);
    }
}
