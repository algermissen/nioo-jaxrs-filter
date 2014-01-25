package net.jalg.nioo.rs.server;


import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

/**
 * Root resource (exposed at "myresource" path)
 */

@Path("bodyHashValidatingResource")
public class BodyHashValidatingResource {

    @POST
    @Produces(MediaType.TEXT_PLAIN)
    @HawkProtected(realm = "test" , validateRequestPayload = true,hashResponsePayload = false)
    public String post(@Context SecurityContext sc, String body) {

        return body + ":" + sc.getUserPrincipal().getName();
    }
}

