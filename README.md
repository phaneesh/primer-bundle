# Dropwizard Primer Bundle [![Travis build status](https://travis-ci.org/phaneesh/primer-bundle.svg?branch=master)](https://travis-ci.org/phaneesh/msgpack-bundle)

This bundle adds Primer JWT service support for dropwizard.
This bundle compiles only on Java 8.
 
## Dependencies
* Primer

## Usage
The bundle adds Primer JWT service support for dropwizard. 
This makes it easier to secure the your API with JWT and a robust claims negotiation. 
 
### Build instructions
  - Clone the source:

        git clone github.com/phaneesh/primer-bundle

  - Build

        mvn install

### Maven Dependency
Use the following repository:
```xml
<repository>
    <id>clojars</id>
    <name>Clojars repository</name>
    <url>https://clojars.org/repo</url>
</repository>
```
Use the following maven dependency:
```xml
<dependency>
    <groupId>io.dropwizard.primer</groupId>
    <artifactId>primer-bundle</artifactId>
    <version>0.0.1</version>
</dependency>
```

### Using Primer bundle

#### Bootstrap
```java
    @Override
    public void initialize(final Bootstrap...) {
        bootstrap.addBundle(new PrimerBundle() {
            
            public PrimerBundleConfiguration getPrimerConfiguration() {
                ...
            }
        });
    }
```

LICENSE
-------

Copyright 2016 Phaneesh Nagaraja <phaneesh.n@gmail.com>.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.