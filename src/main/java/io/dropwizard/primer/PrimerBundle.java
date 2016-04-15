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

import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import feign.Feign;
import feign.Logger;
import feign.Target;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import feign.okhttp.OkHttpClient;
import feign.ranger.RangerTarget;
import feign.slf4j.Slf4jLogger;
import io.dropwizard.Configuration;
import io.dropwizard.ConfiguredBundle;
import io.dropwizard.lifecycle.Managed;
import io.dropwizard.primer.auth.PrimerAuthenticatorRequestFilter;
import io.dropwizard.primer.cache.TokenCacheManager;
import io.dropwizard.primer.client.PrimerClient;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.exception.PrimerExceptionMapper;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import io.dropwizard.primer.model.PrimerRangerEndpoint;
import io.dropwizard.primer.model.PrimerSimpleEndpoint;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.RetryNTimes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * @author phaneesh
 */
@Slf4j
public abstract class PrimerBundle<T extends Configuration> implements ConfiguredBundle<T> {

    private static List<String> whiteList = new ArrayList<>();

    public abstract PrimerBundleConfiguration getPrimerConfiguration(T configuration);

    /**
     * Default method which provides a default curator for service discovery to work in case there is no other
     * curator instance available. Override this to supply your own creator
     * @param configuration Application configuration
     * @return CuratorFramework
     */
    public CuratorFramework getCurator(T configuration) {
        final PrimerBundleConfiguration primerBundleConfiguration = getPrimerConfiguration(configuration);
        final val config = (PrimerRangerEndpoint)primerBundleConfiguration.getEndpoint();
        final CuratorFramework curatorFramework = CuratorFrameworkFactory.builder()
                .connectString(config.getZookeeper())
                .namespace(config.getNamespace()).retryPolicy(new RetryNTimes(1000, 500)).build();
        curatorFramework.start();
        return curatorFramework;
    }

    @Override
    public void initialize(Bootstrap<?> bootstrap) {
        bootstrap.getObjectMapper().registerSubtypes(new NamedType(PrimerSimpleEndpoint.class, "simple"));
        bootstrap.getObjectMapper().registerSubtypes(new NamedType(PrimerRangerEndpoint.class, "ranger"));
    }

    @Override
    public void run(T configuration, Environment environment) throws Exception {
        final val primerConfig = getPrimerConfiguration(configuration);
        initializeWhiteList(primerConfig);
        final JacksonDecoder decoder = new JacksonDecoder();
        final JacksonEncoder encoder = new JacksonEncoder();
        final Slf4jLogger logger = new Slf4jLogger();
        PrimerClient primerClient = Feign.builder()
                .decoder(decoder)
                .encoder(encoder)
                .errorDecoder((methodKey, response) -> {
                    try {
                        final PrimerError error = environment.getObjectMapper().readValue(response.body().asInputStream(), PrimerError.class);
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
                .target(getPrimerTarget(configuration, environment));

        environment.lifecycle().manage(new Managed() {
            @Override
            public void start() throws Exception {
                TokenCacheManager.init(primerConfig);
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
                .whitelist(whiteList)
        .build());
    }

    private Target<PrimerClient> getPrimerTarget(T configuration, Environment environment) {
        final val primerConfig = getPrimerConfiguration(configuration);
        switch(primerConfig.getEndpoint().getType()) {
            case "simple":
                final val endpoint = (PrimerSimpleEndpoint)primerConfig.getEndpoint();
                return new Target.HardCodedTarget<>(PrimerClient.class,
                        String.format("http://%s:%d", endpoint.getHost(), endpoint.getPort()));
            case "ranger":
                final val config = (PrimerRangerEndpoint)primerConfig.getEndpoint();
                try {
                    new RangerTarget<>(PrimerClient.class, config.getEnvironment(), config.getNamespace(),
                            config.getService(), getCurator(configuration), false, environment.getObjectMapper());
                } catch (Exception e) {
                    log.error("Error creating ranger endpoint for primer", e);
                    return null;
                }
        }
        return null;
    }

    private void initializeWhiteList(final PrimerBundleConfiguration configuration) {
        configuration.getWhileListUrl().forEach( p -> whiteList.add(generatePathExpression(p)));
    }

    private String generatePathExpression(final String path) {
        return path.replaceAll("\\{(([^/])+\\})", "(([^/])+)");
    }
}
