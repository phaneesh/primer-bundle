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

import com.codahale.metrics.health.HealthCheckRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import io.dropwizard.Configuration;
import io.dropwizard.jersey.DropwizardResourceConfig;
import io.dropwizard.jersey.setup.JerseyEnvironment;
import io.dropwizard.jetty.MutableServletContextHandler;
import io.dropwizard.lifecycle.setup.LifecycleEnvironment;
import io.dropwizard.primer.auth.authorizer.PrimerAnnotationAuthorizer;
import io.dropwizard.primer.auth.authorizer.PrimerRoleAuthorizer;
import io.dropwizard.primer.auth.token.PrimerTokenProvider;
import io.dropwizard.primer.model.PrimerAuthorization;
import io.dropwizard.primer.model.PrimerAuthorizationMatrix;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import io.dropwizard.primer.model.PrimerSimpleEndpoint;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import java.util.Collections;
import org.joda.time.DateTime;
import org.junit.Before;

import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author phaneesh
 */
public abstract class BaseTest {

    protected final HealthCheckRegistry healthChecks = mock(HealthCheckRegistry.class);
    protected final JerseyEnvironment jerseyEnvironment = mock(JerseyEnvironment.class);
    protected final LifecycleEnvironment lifecycleEnvironment = new LifecycleEnvironment();
    protected static final Environment environment = mock(Environment.class);
    protected final Bootstrap<?> bootstrap = mock(Bootstrap.class);
    protected final Configuration configuration = mock(Configuration.class);
    protected final String primerCookie = "P_SESSIONID";

    protected static final ObjectMapper mapper = new ObjectMapper();

    protected final PrimerBundle<Configuration> bundle = new PrimerBundle<Configuration>() {


        @Override
        public PrimerBundleConfiguration getPrimerConfiguration(Configuration configuration) {
            return primerBundleConfiguration;
        }

        @Override
        public Set<String> withWhiteList(Configuration configuration) {
            return primerBundleConfiguration.getWhileListUrl();
        }

        @Override
        public PrimerAuthorizationMatrix
        withAuthorization(Configuration configuration) {
            return PrimerAuthorizationMatrix.builder()
                    .authorizations(Collections.singletonList(PrimerAuthorization.builder()
                            .type("dynamic")
                            .method("GET")
                            .role("test")
                            .url("simple/auth/test")
                    .build())).build();
        }

        @Override
        public PrimerAnnotationAuthorizer authorizer() {
            return PrimerRoleAuthorizer.builder().build();
        }

        @Override
        public String getPrimerConfigAttribute() {
            return "primer";
        }

        @Override
        public PrimerTokenProvider getPrimerTokenProvider() {
            return PrimerTokenProvider.builder().primerCookie(primerCookie).build();
        }
    };

    protected PrimerBundleConfiguration primerBundleConfiguration;

    protected HmacSHA512Signer hmacSHA512Signer;

    public JsonWebToken webToken = JsonWebToken.builder()
            .header(
                    JsonWebTokenHeader.HS512()
            )
            .claim(JsonWebTokenClaim
                    .builder()
                    .expiration(DateTime.now().plusYears(1))
                    .subject("test")
                    .issuer("test")
                    .issuedAt(DateTime.now())
                    .param("user_id", "test")
                    .param("role", "test")
                    .param("name", "test")
                    .param("type", "dynamic")
                    .build())
            .build();

    public String token = null;

    protected static BundleTestResource bundleTestResource = new BundleTestResource();

    @Before
    public void setup() throws Exception {
        when(jerseyEnvironment.getResourceConfig()).thenReturn(new DropwizardResourceConfig());
        when(environment.jersey()).thenReturn(jerseyEnvironment);
        when(environment.lifecycle()).thenReturn(lifecycleEnvironment);
        when(environment.healthChecks()).thenReturn(healthChecks);
        when(environment.getObjectMapper()).thenReturn(mapper);
        when(bootstrap.getObjectMapper()).thenReturn(new ObjectMapper());
        when(environment.getApplicationContext()).thenReturn(new MutableServletContextHandler());

        primerBundleConfiguration = PrimerBundleConfiguration.builder()
                .cacheExpiry(30)
                .cacheMaxSize(100)
                .clockSkew(60)
                .endpoint(new PrimerSimpleEndpoint("simple", "localhost", 9999))
                .privateKey("thisisatestkey")
                .prefix("Bearer")
                .whiteList("simple/noauth/test")
                .build();

        bundle.initialize(bootstrap);

        bundle.run(configuration, environment);

        hmacSHA512Signer = new HmacSHA512Signer(primerBundleConfiguration.getPrivateKey().getBytes());

        token = hmacSHA512Signer.sign(webToken);

        lifecycleEnvironment.getManagedObjects().forEach(object -> {
            try {
                object.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        environment.jersey().register(bundleTestResource);
    }
}
