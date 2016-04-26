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
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.Hashing;
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

import java.util.Set;

/**
 * @author phaneesh
 */
@Slf4j
public class PrimerAuthorizationRegistry {

    private static ImmutableMap<String, String> urlIndex;

    private static ImmutableMap<String, PrimerAuthorization> authList;

    private static ImmutableSet<String> whiteList;

    public static void init(PrimerAuthorizationMatrix matrix, Set<String> whiteListUrls) {
        val authListBuilder = ImmutableMap.<String, PrimerAuthorization>builder();
        val urlIndexBuilder = ImmutableMap.<String, String>builder();
        if(matrix != null) {
            matrix.getAuthorizations().forEach( auth -> {
                String indexId = Hashing.murmur3_128().hashString(auth.getUrl(), Charsets.UTF_8).toString();
                urlIndexBuilder.put(indexId, generatePathExpression(auth.getUrl()));
                authListBuilder.put(indexId, auth);
            });
        }
        authList = authListBuilder.build();
        urlIndex = urlIndexBuilder.build();
        val whiteListBuilder = ImmutableSet.<String>builder();
        whiteListUrls.forEach(p -> whiteListBuilder.add(generatePathExpression(p)));
        whiteList = whiteListBuilder.build();
    }

    private static String generatePathExpression(final String path) {
        return path.replaceAll("\\{(([^/])+\\})", "(([^/])+)");
    }

    public static boolean authorize(final String path, final String role, final String method, final String token,
                                    final JsonWebToken jsonWebToken) throws PrimerException {
        val index = urlIndex.entrySet().stream().filter(e -> path.matches(e.getValue())).findFirst();
        if(!index.isPresent())
            return false;

        //Short circuit for method auth failure
        if(!isAuthorized(index.get().getKey(), method, role))
            return false;
        if(TokenCacheManager.checkCache(token)) {
            return true;
        }
        switch (authList.get(index.get().getKey()).getType()) {
            case "dynamic":
                return verify(jsonWebToken, token);
            case "static":
                return verifyStatic(jsonWebToken, token);
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
