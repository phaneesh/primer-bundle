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
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import feign.Feign;
import feign.Logger;
import feign.httpclient.ApacheHttpClient;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import feign.slf4j.Slf4jLogger;
import io.dropwizard.primer.client.PrimerClient;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.core.ServiceUser;
import io.dropwizard.primer.core.VerifyResponse;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.testing.junit.ResourceTestRule;
import lombok.val;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.time.Instant;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * @author phaneesh
 */
public class PrimerBundleTests extends BaseTest {

    @ClassRule
    public static ResourceTestRule resources = ResourceTestRule.builder()
            .addResource(bundleTestResource)
            .build();

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(9090);

    @Test
    public void testWhitelistedUrl() {
        val result = resources.client().target("/simple/noauth/test").request()
                .get(Response.class);
        assertEquals(200, result.getStatus());
    }

    @Test
    public void testVerifyCall() throws JsonProcessingException {
        stubFor(post(urlEqualTo("/v1/verify/test/test"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(mapper.writeValueAsBytes(VerifyResponse.builder()
                                .expiresAt(Instant.now().plusSeconds(10000).toEpochMilli())
                                .token("test")
                                .userId("test")
                                .build()))));
        final JacksonDecoder decoder = new JacksonDecoder();
        final JacksonEncoder encoder = new JacksonEncoder();
        final Slf4jLogger logger = new Slf4jLogger();
        PrimerClient primerClient = Feign.builder()
                .decoder(decoder)
                .encoder(encoder)
                .errorDecoder((methodKey, response) -> {
                    try {
                        final PrimerError error =  environment.getObjectMapper().readValue(response.body().asInputStream(), PrimerError.class);
                        return PrimerException.builder()
                                .message(error.getMessage())
                                .errorCode(error.getErrorCode())
                                .status(response.status())
                                .build();
                    } catch (IOException e) {
                        return PrimerException.builder()
                                .status(response.status())
                                .errorCode("PR000")
                                .message(e.getMessage()).build();
                    }
                })
                .client(new ApacheHttpClient())
                .logger(logger)
                .logLevel(Logger.Level.BASIC)
                .target(PrimerClient.class, "http://localhost:9090");
        try {
            final VerifyResponse verifyResponse = primerClient.verify(
                    "test",
                    "test",
                    "test",
                    ServiceUser.builder()
                            .id("test")
                            .name("test")
                            .role("test")
                            .build());
            assertEquals("test", verifyResponse.getUserId());
            assertEquals("test", verifyResponse.getToken());
        } catch (PrimerException e) {
            fail();
        }
    }

    @Test
    public void testPrimerAuthAnnotation() throws JsonProcessingException {
        stubFor(post(urlEqualTo("/v1/verify/test/test"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(mapper.writeValueAsBytes(VerifyResponse.builder()
                                .expiresAt(Instant.now().plusSeconds(10000).toEpochMilli())
                                .token(hmacToken)
                                .userId("test")
                                .build()))));

        val result = resources.client().target("/annotation/auth").request()
                .get(Response.class);
        assertEquals(200, result.getStatus());
    }
}
