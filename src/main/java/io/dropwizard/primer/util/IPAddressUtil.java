package io.dropwizard.primer.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by pavan.kumar on 2019-09-24
 */
@Slf4j
public class IPAddressUtil {

    private static final String X_REAL_IP = "x-real-ip";
    private static final String X_FORWARDED_FOR = "x-forwarded-for";

    public static String getIP(HttpServletRequest httpServletRequest) {
        if (StringUtils.isNotBlank(httpServletRequest.getHeader(X_REAL_IP)))
            return httpServletRequest.getHeader(X_REAL_IP);

        if (StringUtils.isNotBlank(httpServletRequest.getHeader(X_FORWARDED_FOR))) {
            String[] ips = httpServletRequest.getHeader(X_FORWARDED_FOR).split(",");
            if (ips.length > 0)
                return ips[0];
        }

        return httpServletRequest.getRemoteAddr();
    }

}
