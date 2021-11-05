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

package io.dropwizard.primer.model;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;

import javax.annotation.Nonnegative;

/**
 * @author phaneesh
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class PrimerSimpleEndpoint extends PrimerEndpoint {

    @NonNull
    private final String type;

    @NonNull
    private final String host;

    @Nonnegative
    private final int port;

    //Backward compatibility for <=2.0.17
    public PrimerSimpleEndpoint(String type, String host, int port) {
        this(type, host, port, "", false);
    }

    private int getDefaultPort() {
        if (isSecure()) {
            return 443;
        } else {
            return 80;
        }
    }

    @Builder
    public PrimerSimpleEndpoint(String type, String host, int port, String rootPathPrefix, boolean secure) {
        super(rootPathPrefix, secure);
        this.type = type;
        this.host = host;
        if (port == 0) {
            this.port = getDefaultPort();
        } else {
            this.port = port;
        }
    }
}
