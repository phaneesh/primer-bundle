package io.dropwizard.primer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.dropwizard.primer.model.PrimerEndpoint;
import org.junit.Assert;
import org.junit.Test;

public class ObjectMapperEndpointTest {

    private final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());

    @Test(expected = InvalidTypeIdException.class)
    public void testUnknownEndpoint() throws JsonProcessingException {
        PrimerEndpoint primerEndpoint = objectMapper.readValue(
                "---\n" +
                        "type: unknown\n" +
                        "namespace: test\n" +
                        "service: test\n" +
                        "rootPathPrefix: apis/primer", PrimerEndpoint.class);
        Assert.fail("Parsing shouldn't have succeeded");
    }
}
