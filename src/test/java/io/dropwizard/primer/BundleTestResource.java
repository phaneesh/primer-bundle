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

import io.dropwizard.primer.auth.annotation.Authorize;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

/**
 * @author phaneesh
 */
@Path("/")
public class BundleTestResource {

    @GET
    @Path("/simple/noauth/test")
    public Response testNoAuth() {
        return Response.status(Response.Status.OK).build();
    }

    @GET
    @Path("/simple/auth/test")
    public Response testAuth() {
        return Response.status(Response.Status.OK).build();
    }

    @GET
    @Authorize(value = {"test", "test1"})
    @Path("/annotation/auth")
    public Response testAnnotationAuth() {
        return Response.status(Response.Status.OK).build();
    }

}
