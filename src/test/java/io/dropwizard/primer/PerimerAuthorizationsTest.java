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

package io.dropwizard.primer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import io.dropwizard.primer.auth.PrimerAuthorizationRegistry;
import io.dropwizard.primer.core.VerifyResponse;
import io.dropwizard.primer.exception.PrimerException;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.time.Instant;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author phaneesh
 */
public class PerimerAuthorizationsTest extends BaseTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(9999);

    @Test
    public void testWhiteListPresent() {
        assertTrue(PrimerAuthorizationRegistry.isWhilisted("simple/noauth/test"));
    }

    @Test
    public void testWhiteListAbsent() {
        assertFalse(PrimerAuthorizationRegistry.isWhilisted("simple/auth/test"));
    }

    @Test
    public void testAuthorizedCall() throws PrimerException, JsonProcessingException {
            stubFor(post(urlEqualTo("/v1/verify/test/test"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody(mapper.writeValueAsBytes(VerifyResponse.builder()
                                    .expiresAt(Instant.now().plusSeconds(10000).toEpochMilli())
                                    .token(token)
                                    .userId("test")
                                    .build()))));
        assertTrue(PrimerAuthorizationRegistry.authorize("simple/auth/test", "test", "GET", token, webToken));
    }

    @Test
    public void testUnAuthorizedCallWithInvalidRole() throws PrimerException {
        assertFalse(PrimerAuthorizationRegistry.authorize("simple/auth/test", "invalid", "GET", token, webToken));
    }

    @Test
    public void testUnAuthorizedCallWithInvalidMethod() throws PrimerException {
        assertFalse(PrimerAuthorizationRegistry.authorize("simple/auth/test", "test", "POST", token, webToken));
    }

    @Test
    public void testUnAuthorizedCallWithInvalidPath() throws PrimerException {
        assertFalse(PrimerAuthorizationRegistry.authorize("simple/auth/test/invalid", "test", "GET", token, webToken));
    }

    @Test
    public void testUnAuthorizedCallWithInvalidRoleAndMethod() throws PrimerException {
        assertFalse(PrimerAuthorizationRegistry.authorize("simple/auth/test", "invalid", "POST", token, webToken));
    }
}
