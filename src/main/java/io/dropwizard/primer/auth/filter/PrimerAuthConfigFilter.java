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

package io.dropwizard.primer.auth.filter;

import com.codahale.metrics.annotation.Metered;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.util.concurrent.UncheckedExecutionException;
import io.dropwizard.primer.auth.AuthFilter;
import io.dropwizard.primer.auth.AuthType;
import io.dropwizard.primer.auth.PrimerAuthorizationRegistry;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import javax.annotation.Priority;
import javax.inject.Singleton;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;


/**
 * @author phaneesh
 */
@Slf4j
@Provider
@Priority(Priorities.AUTHENTICATION)
@Singleton
public class PrimerAuthConfigFilter extends AuthFilter {

    @Builder
    public PrimerAuthConfigFilter(final PrimerBundleConfiguration configuration, final ObjectMapper objectMapper) {
        super(AuthType.CONFIG, configuration, objectMapper);
    }

    @Override
    @Metered(name = "primer")
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (!configuration.isEnabled() || !configuration.getAuthTypesEnabled().getOrDefault(AuthType.CONFIG, false)) {
            return;
        }
        //Short circuit for all white listed urls
        if (PrimerAuthorizationRegistry.isWhilisted(requestContext.getUriInfo().getPath())) {
            return;
        }
        Optional<String> token = getToken(requestContext);
        if (!token.isPresent()) {
            requestContext.abortWith(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR000").message("Bad request")
                                    .build())).build()
            );
        } else {
            try {
                JsonWebToken webToken = authorize(requestContext, token.get(), this.authType);
                //Stamp authorization headers for downstream services which can
                // use this to stop token forgery & misuse
                stampHeaders(requestContext, webToken);
            } catch (UncheckedExecutionException e) {
                if (e.getCause() instanceof CompletionException) {
                    handleException(e.getCause().getCause(), requestContext, token.get());
                } else {
                    handleException(e.getCause(), requestContext, token.get());
                }
            } catch (Exception e) {
                if (e.getCause() instanceof PrimerException) {
                    handleException(e.getCause(), requestContext, token.get());
                } else {
                    handleException(e, requestContext, token.get());
                }
            }
        }
    }
}
