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

package io.dropwizard.primer.client;

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import io.dropwizard.primer.core.ServiceUser;
import io.dropwizard.primer.core.VerifyResponse;
import io.dropwizard.primer.core.VerifyStaticResponse;
import io.dropwizard.primer.exception.PrimerException;

/**
 * @author phaneesh
 */
public interface PrimerClient {

    @RequestLine("POST /v1/verify/{app}/{id}")
    @Headers({"Content-Type: application/json", "X-Auth-Token: {token}"})
    VerifyResponse verify(@Param("app") final String app,
                          @Param("id") final String id, @Param("token") final String token,
                          final ServiceUser user) throws PrimerException;

    @RequestLine("POST /v1/verify/static/{app}/{id}/{role}")
    @Headers({"Content-Type: application/json", "X-Auth-Token: {token}"})
    VerifyStaticResponse verify(@Param("app") final String app,
                                @Param("id") final String id, @Param("token") final String token,
                                @Param("role") final String role) throws PrimerException;
}
