package net.jalg.nioo.rs.server;


import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

@Path("bodyHashValidatingResource")
public class NonBodyValidatingNonResponseBodySigningResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @HawkProtected(realm = "test" , validateRequestPayload = false,hashResponsePayload = false)
    public String get() {
        return "Test";
    }
}

