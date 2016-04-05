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

import io.dropwizard.testing.junit.ResourceTestRule;
import lombok.val;
import org.junit.ClassRule;
import org.junit.Test;

import javax.ws.rs.core.Response;

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
}
