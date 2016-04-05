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

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import feign.Feign;
import feign.Logger;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import feign.okhttp.OkHttpClient;
import feign.slf4j.Slf4jLogger;
import io.dropwizard.Configuration;
import io.dropwizard.ConfiguredBundle;
import io.dropwizard.lifecycle.Managed;
import io.dropwizard.primer.auth.PrimerAuthenticatorRequestFilter;
import io.dropwizard.primer.cache.TokenCacheManager;
import io.dropwizard.primer.client.PrimerClient;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.exception.PrimerExceptionMapper;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

import java.nio.charset.StandardCharsets;

/**
 * @author phaneesh
 */
public abstract class PrimerBundle<T extends Configuration> implements ConfiguredBundle<T> {

    private static PrimerClient primerClient;

    public abstract PrimerBundleConfiguration getPrimerConfiguration(T configuration);

    @Override
    public void initialize(Bootstrap<?> bootstrap) {


    }

    @Override
    public void run(T configuration, Environment environment) throws Exception {
        final JacksonDecoder decoder = new JacksonDecoder();
        final JacksonEncoder encoder = new JacksonEncoder();
        final Slf4jLogger logger = new Slf4jLogger();

        primerClient = Feign.builder()
                .decoder(decoder)
                .encoder(encoder)
                .errorDecoder((methodKey, response) -> PrimerException.builder()
                        .status(javax.ws.rs.core.Response.Status.fromStatusCode(response.status()))
                        .errorCode("PR000")
                        .message(response.body().toString()).build())
                .client(new OkHttpClient())
                .logger(logger)
                .logLevel(Logger.Level.BASIC)
                .target(PrimerClient.class, String.format("http://%s:%d", getPrimerConfiguration(configuration).getHost(), getPrimerConfiguration(configuration).getPort()));

        environment.lifecycle().manage(new Managed() {
            @Override
            public void start() throws Exception {
                TokenCacheManager.init(getPrimerConfiguration(configuration));
            }

            @Override
            public void stop() throws Exception {

            }
        });
        environment.jersey().register(new PrimerExceptionMapper());
        final JsonWebTokenParser tokenParser = new DefaultJsonWebTokenParser();
        final byte[] secretKey = getPrimerConfiguration(configuration).getPrivateKey().getBytes(StandardCharsets.UTF_8);
        final HmacSHA512Verifier tokenVerifier = new HmacSHA512Verifier(secretKey);
        environment.jersey().register(PrimerAuthenticatorRequestFilter.builder()
                .configuration(getPrimerConfiguration(configuration))
                .primerClient(primerClient)
                .tokenParser(tokenParser)
                .verifier(tokenVerifier)
        .build());
    }
}
