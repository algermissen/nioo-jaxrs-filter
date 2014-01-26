package net.jalg.nioo.rs.server;


import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("responseBodySigningResource")
public class ResponseBodySigningResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @HawkProtected(realm = "test" , validateRequestPayload = false,hashResponsePayload = true)
    public String get() {
        return "Test";
    }
}

