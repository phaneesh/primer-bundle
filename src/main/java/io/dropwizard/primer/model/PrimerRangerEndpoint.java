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

import lombok.*;

/**
 * @author phaneesh
 */
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class PrimerRangerEndpoint extends PrimerEndpoint {
    private String type;

    private String namespace;

    private String zookeeper;

    private String service;

    private String environment;

    //Backward compatibility for <=2.0.17
    public PrimerRangerEndpoint(String type, String namespace, String zookeeper, String service, String environment) {
        this(type, namespace, zookeeper, service, environment, "", false);
    }

    @Builder
    private PrimerRangerEndpoint(String type, String namespace, String zookeeper, String service, String environment, String rootPathPrefix, boolean secure) {
        super(rootPathPrefix, secure);
        this.type = type;
        this.namespace = namespace;
        this.zookeeper = zookeeper;
        this.service = service;
        this.environment = environment;
    }
}
