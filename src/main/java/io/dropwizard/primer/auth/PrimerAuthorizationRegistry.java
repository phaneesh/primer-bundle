/*
 * Copyright 2016 Phaneesh Nagaraja <phaneesh.n@gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.dropwizard.primer.auth;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import io.dropwizard.primer.PrimerBundle;
import io.dropwizard.primer.cache.TokenCacheManager;
import io.dropwizard.primer.core.ServiceUser;
import io.dropwizard.primer.core.VerifyResponse;
import io.dropwizard.primer.core.VerifyStaticResponse;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerAuthorization;
import io.dropwizard.primer.model.PrimerAuthorizationMatrix;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.regex.Pattern;

/**
 * @author phaneesh
 */
@Slf4j
public class PrimerAuthorizationRegistry {

    private static Map<String, PrimerAuthorization> authList;

    private static List<String> whiteList;

    private static List<String> urlPatterns;


    public static void init(PrimerAuthorizationMatrix matrix, Set<String> whiteListUrls) {
        authList = new HashMap<>();
        whiteList = new ArrayList<>();
        urlPatterns = new ArrayList<>();
        val urlToAuthMap = new HashMap<String, PrimerAuthorization>();
        val tokenMatch = Pattern.compile("\\{(([^/])+\\})");
        if(matrix != null) {
            matrix.getAuthorizations().forEach( auth -> {
                final String pattern = generatePathExpression(auth.getUrl());
                urlPatterns.add(pattern);
                urlToAuthMap.put(pattern, auth);
            });
            matrix.getStaticAuthorizations().forEach( auth -> {
                final String pattern = generatePathExpression(auth.getUrl());
                urlPatterns.add(pattern);
                urlToAuthMap.put(pattern, auth);
            });
            matrix.getAutoAuthorizations().forEach( auth -> {
                final String pattern = generatePathExpression(auth.getUrl());
                urlPatterns.add(pattern);
                urlToAuthMap.put(pattern, auth);
            });
            Collections.sort(urlPatterns, (o1, o2) -> tokenMatch.matcher(o2).groupCount() - tokenMatch.matcher(o1).groupCount());
            Collections.sort(urlPatterns, (o1, o2) -> o2.compareTo(o1));
            urlPatterns.forEach( pattern -> authList.put(pattern, urlToAuthMap.get(pattern)));
        }
        whiteListUrls.forEach( url -> whiteList.add(generatePathExpression(url)));
        Collections.sort(whiteList, (o1, o2) -> tokenMatch.matcher(o2).groupCount() - tokenMatch.matcher(o1).groupCount());
        Collections.sort(whiteList, (o1, o2) -> o2.compareTo(o1));
    }

    private static String generatePathExpression(final String path) {
        return path.replaceAll("\\{(([^/])+\\})", "(([^/])+)");
    }

    public static boolean authorize(final String path, final String role, final String method, final String token,
                                    final JsonWebToken jsonWebToken) throws PrimerException {
        if(TokenCacheManager.checkCache(token)) {
            return true;
        }

        val index = urlPatterns.stream().filter(path::matches).findFirst();
        if(!index.isPresent())
            return false;

        //Short circuit for method auth failure
        if(!isAuthorized(index.get(), method, role))
            return false;
        switch (authList.get(index.get()).getType()) {
            case "dynamic":
                return verify(jsonWebToken, token, "dynamic");
            case "static":
                return verify(jsonWebToken, token, "static");
            case "auto":
                final String type = (String)jsonWebToken.claim().getParameter("type");
                return verify(jsonWebToken, token, type);
            default:
                return false;
        }
    }

    public static boolean isWhilisted(final String path) {
        return whiteList.stream()
                .filter(path::matches).findFirst().isPresent();
    }

    private static boolean isAuthorized(final String id, final String method, final String role) {
        return authList.get(id).getRoles().contains(role) && authList.get(id).getMethods().contains(method);
    }

    private static boolean verify(JsonWebToken webToken, String token, String type) throws PrimerException {
        switch (type) {
            case "dynamic":
                return verify(webToken, token);
            case "static":
                return verifyStatic(webToken, token);
        }
        return false;
    }

    private static boolean verify(JsonWebToken webToken, String token) throws PrimerException {
        final VerifyResponse verifyResponse = PrimerBundle.getPrimerClient().verify(
                webToken.claim().issuer(),
                webToken.claim().subject(),
                token,
                ServiceUser.builder()
                        .id((String)webToken.claim().getParameter("user_id"))
                        .name((String)webToken.claim().getParameter("name"))
                        .role((String)webToken.claim().getParameter("role"))
                        .build()
        );
        val result = (!StringUtils.isBlank(verifyResponse.getToken()) && !StringUtils.isBlank(verifyResponse.getUserId()));
        if(result) {
            TokenCacheManager.cache(token);
        }
        return result;
    }

    private static boolean verifyStatic(JsonWebToken webToken, String token) throws PrimerException {
        final VerifyStaticResponse verifyStaticResponse = PrimerBundle.getPrimerClient().verify(webToken.claim().issuer(),
                webToken.claim().subject(), token, (String)webToken.claim().getParameter("role") );
        val result = (!StringUtils.isBlank(verifyStaticResponse.getToken()) && !StringUtils.isBlank(verifyStaticResponse.getId()));
        if(result) {
            TokenCacheManager.cache(token);
        }
        return result;
    }

}
