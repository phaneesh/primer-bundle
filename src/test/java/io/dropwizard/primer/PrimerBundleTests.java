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

import feign.Feign;
import feign.Logger;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import feign.okhttp.OkHttpClient;
import feign.slf4j.Slf4jLogger;
import io.dropwizard.primer.client.PrimerClient;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.core.ServiceUser;
import io.dropwizard.primer.core.VerifyResponse;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.testing.junit.ResourceTestRule;
import lombok.val;
import org.junit.ClassRule;
import org.junit.Test;

import javax.ws.rs.core.Response;

import java.io.IOException;

import static org.junit.Assert.assertTrue;

/**
 * @author phaneesh
 */
public class PrimerBundleTests extends BaseTest {

    @ClassRule
    public static ResourceTestRule resources = ResourceTestRule.builder()
            .addResource(bundleTestResource)
            .build();

    @Test
    public void testWhitelistedUrl() {
        val result = resources.client().target("/simple/noauth/test").request()
                .get(Response.class);
        assertTrue(result.getStatus() == 200);
    }

    @Test
    public void testVerifyCall() {
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
                .client(new OkHttpClient())
                .logger(logger)
                .logLevel(Logger.Level.BASIC)
                .target(PrimerClient.class, String.format("http://primer.stg-mesos.phonepe.int"));
        try {
            final VerifyResponse verifyResponse = primerClient.verify(
                    "test",
                    "Santanu",
                    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNDYwMDI3OTk3LCJpYXQiOjE0NjAwMjQzOTcsInN1YiI6IlNhbnRhbnUiLCJyb2xlIjoibG9zZXIiLCJ1c2VyX2lkIjoic2FudGFudSIsIm5hbWUiOiJub3BpbXAifQ.YnRt-i3euUMXsYKxsUVNw1-PB_2kxX3ujr9knkCispZdKXHRja04s3Uc92zk35tr16MjRv2riZGXa6PEcnHbKg",
                    ServiceUser.builder()
                            .id("santanu")
                            .name("nopimp")
                            .role("loser")
                            .build());
        } catch (PrimerException e) {
            e.printStackTrace();
        }
    }
}
