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
import com.google.common.util.concurrent.UncheckedExecutionException;
import io.dropwizard.primer.auth.AuthFilter;
import io.dropwizard.primer.auth.AuthType;
import io.dropwizard.primer.auth.PrimerAuthorizationRegistry;
import io.dropwizard.primer.auth.token.PrimerTokenProvider;
import io.dropwizard.primer.core.PrimerError;
import io.dropwizard.primer.exception.PrimerException;
import io.dropwizard.primer.util.CryptUtil;
import io.dropwizard.primer.model.PrimerConfigurationHolder;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import javax.annotation.Priority;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Singleton;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.CompletionException;


/**
 * @author phaneesh
 */
@Slf4j
@Provider
@Priority(Priorities.AUTHENTICATION)
@Singleton
public class PrimerAuthConfigFilter extends AuthFilter {

  private final SecretKeySpec secretKeySpec;

  private final GCMParameterSpec ivParameterSpec;

  private final JwtConsumer validationsSkippedJwtConsumer;

  @Builder
  public PrimerAuthConfigFilter(final PrimerConfigurationHolder configHolder, final ObjectMapper objectMapper,
                                final SecretKeySpec secretKeySpec, final GCMParameterSpec ivParameterSpec,
                                final PrimerTokenProvider primerTokenProvider) {
    super(AuthType.CONFIG, configHolder, objectMapper, primerTokenProvider);
    this.secretKeySpec = secretKeySpec;
    this.ivParameterSpec = ivParameterSpec;
    validationsSkippedJwtConsumer = new JwtConsumerBuilder()
            .setSkipSignatureVerification()
            .setSkipAllDefaultValidators()
            .build();
  }

  @Override
  @Metered(name = "primer")
  public void filter(ContainerRequestContext requestContext) throws IOException {
    // Do not proceed further with Auth if its disabled or whitelisted
    if (!isEnabled())
      return;

    Optional<String> token = getToken(requestContext);
    if (!token.isPresent()) {
      if(isWhitelisted(requestContext)){
        return;
      }
      requestContext.abortWith(
          Response.status(configHolder.getConfig().getAbsentTokenStatus())
              .entity(objectMapper.writeValueAsBytes(PrimerError.builder().errorCode("PR000").message("Bad request")
                  .build())).build()
      );
    } else {
      try {
        final String decryptedToken = CryptUtil.tokenDecrypt(token.get(), secretKeySpec, ivParameterSpec);
        JwtClaims jwtClaims;
        if(isWhitelisted(requestContext)) {
          jwtClaims = validationsSkippedJwtConsumer.processToClaims(decryptedToken);
        } else {
          jwtClaims = authorize(requestContext, decryptedToken, this.authType);
        }
        //Stamp authorization headers for downstream services which can
        // use this to stop token forgery & misuse
        primerTokenProvider.stampHeaders(requestContext, jwtClaims, decryptedToken);
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

  private boolean isEnabled() {
    return configHolder.getConfig().isEnabled()
        && configHolder.getConfig().getAuthTypesEnabled().getOrDefault(AuthType.CONFIG, false);
  }

  private boolean isWhitelisted(ContainerRequestContext requestContext) {
    //Short circuit for all white listed urls
    return PrimerAuthorizationRegistry.isWhilisted(requestContext.getUriInfo().getPath());
  }
}
