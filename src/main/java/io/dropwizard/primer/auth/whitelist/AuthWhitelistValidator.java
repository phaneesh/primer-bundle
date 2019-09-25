package io.dropwizard.primer.auth.whitelist;

import io.dropwizard.primer.auth.annotation.AuthWhitelist;
import io.dropwizard.primer.util.IPAddressUtil;
import lombok.Builder;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;
import java.util.Arrays;

/**
 * Created by pavan.kumar on 2019-09-23
 */
public class AuthWhitelistValidator implements WhitelistType.Visitor<Boolean> {

    private final AuthWhitelist authWhitelist;
    private final HttpServletRequest httpServletRequest;

    @Builder
    public AuthWhitelistValidator(AuthWhitelist authWhitelist, HttpServletRequest httpServletRequest) {
        this.authWhitelist = authWhitelist;
        this.httpServletRequest = httpServletRequest;
    }

    /**
     * Optional authorization.
     * Returns true if enabled and auth headers are absent in the servlet request.
     * Returns false if auth header is present.
     *
     * @return Boolean
     */
    @Override
    public Boolean visitOptional() {
        return Boolean.parseBoolean(authWhitelist.value())
                && StringUtils.isNotBlank(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION));
    }

    /**
     * Returns true if the httpServletRequest source IP matches the
     * comma separated list of whitelisted IPs.
     *
     * @return Boolean
     */
    @Override
    public Boolean visitIP() {
        return Arrays
                .asList(authWhitelist.value().split(","))
                .contains(IPAddressUtil.getIP(httpServletRequest));
    }
}
