package net.jalg.nioo.rs.server;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.jalg.hawkj.Algorithm;
import net.jalg.hawkj.AuthorizationHeader;
import net.jalg.hawkj.HawkContext;
import net.jalg.hawkj.util.Charsets;
import org.glassfish.grizzly.http.server.HttpServer;

import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.security.Principal;

import static org.junit.Assert.assertEquals;

/**
 * @author Jan Algermissen <algermissen@acm.org>
 */
public class HawkServerFilterTest {

    public static final String HOST = "localhost";
    public static final int PORT = 8082;
    public static final String BASE_URI = "http://" + HOST + ":" + PORT + "/myapp/";

    public static final String ID = "abc";
    public static final String PWD = "def";
    public static Algorithm ALGORITHM = Algorithm.SHA_256;

    private HttpServer server;
    private Client client;
    private WebTarget baseTarget;

    @Before
    public void setUp() throws Exception {
        HawkFeature hawkFeature = new HawkFeature(new TestProvider());
        final ResourceConfig rc = new ResourceConfig().packages("net.jalg.nioo.rs.server")
                .register(hawkFeature);
        client= ClientBuilder.newClient();
        baseTarget = client.target(BASE_URI);
        server = GrizzlyHttpServerFactory.createHttpServer(URI.create(BASE_URI), rc);
    }

    @After
    public void tearDown() throws Exception {
        server.stop();
    }

    @Test
    public void testThatFilterValidatesCorrectSignature() {
        WebTarget target = baseTarget.path(UriBuilder.fromResource(NonBodyValidatingNonResponseBodySigningResource.class).build().getPath());
        HawkContext hc = HawkContext.request("GET", target.getUri().getPath(), HOST, PORT).credentials(ID, PWD, ALGORITHM).build();
        AuthorizationHeader ah = hc.createAuthorizationHeader();

        Response response = target.request().header("Authorization", ah.toString()).get();

        assertEquals(200,response.getStatus());

    }

    @Test
    public void testThatFilterDetectsInvalidSignature() {
        WebTarget target = baseTarget.path(UriBuilder.fromResource(NonBodyValidatingNonResponseBodySigningResource.class).build().getPath());
        HawkContext hc = HawkContext.request("GET", target.getUri().getPath(), HOST, PORT).credentials(ID, PWD + "CHANGE", ALGORITHM).build();
        AuthorizationHeader ah = hc.createAuthorizationHeader();

        Response response = target.request().header("Authorization", ah.toString()).get();

        assertEquals(401,response.getStatus());

    }

    @Test
    public void testThatFilterValidatesCorrectBodyHash() {
        String body = "abcdefg";
        String contentType = "text/plain";
        WebTarget target = baseTarget.path(UriBuilder.fromResource(BodyHashValidatingResource.class).build().getPath());
        HawkContext hc = HawkContext.request("POST", target.getUri().getPath(), HOST, PORT).credentials(ID, PWD, ALGORITHM)
                .body(body.getBytes(Charsets.UTF_8),contentType).build();
        AuthorizationHeader ah = hc.createAuthorizationHeader();

        Response response = target.request().header("Authorization", ah.toString()).post(Entity.text(body));
//      FIXME  for( String key :  response.getStringHeaders().keySet()) {
//            System.out.println( key + ": " + response.getHeaderString(key));
//        }

        assertEquals(200,response.getStatus());

        String entity = response.readEntity(String.class);
        assertEquals(body + ":" + ID, entity);

    }

    @Test
    public void testThatFilterDetectsInvalidBodyHash() {
        String body = "abcdefg";
        String contentType = "text/plain";
        WebTarget target = baseTarget.path(UriBuilder.fromResource(BodyHashValidatingResource.class).build().getPath());
        HawkContext hc = HawkContext.request("POST", target.getUri().getPath(), HOST, PORT).credentials(ID, PWD, ALGORITHM)
                .body(body.getBytes(Charsets.UTF_8),contentType).build();
        AuthorizationHeader ah = hc.createAuthorizationHeader();

        Response response = target.request().header("Authorization", ah.toString()).post(Entity.text(body + "CHANGED"));

        assertEquals(401,response.getStatus());

    }

    @Test
    public void testThatFilterDetectsMissingBodyHash() {
        String body = "abcdefg";
        WebTarget target = baseTarget.path(UriBuilder.fromResource(BodyHashValidatingResource.class).build().getPath());
        HawkContext hc = HawkContext.request("POST", target.getUri().getPath(), HOST, PORT).credentials(ID, PWD, ALGORITHM).build();
        AuthorizationHeader ah = hc.createAuthorizationHeader();

        Response response = target.request().header("Authorization", ah.toString()).post(Entity.text(body));

        assertEquals(401,response.getStatus());

    }



    public static class TestProvider implements HawkServerProvider {
        @Override
        public int getConfiguredValidationPort() {
            return -1;
        }

        @Override
        public String getConfiguredValidationHost() {
            return null;
        }

        @Override
        public HawkCredentials getHawkCredentials(String realm,String id) throws HawkProviderException {
            return new TestCredentials(new TestProvidedUser(id));
        }

        @Override
        public void noteNonce(String id, long ts, String nonce) {
            ;
        }

        @Override
        public boolean nonceHasBeenUsedBefore(String id, long ts, String nonce) throws HawkProviderException {
            return false;
        }

        @Override
        public int getAllowedClockSkew() {
            return 10;
        }
    }

    public static class TestCredentials implements HawkCredentials {

        private ProvidedUser providedUser;

        public TestCredentials(ProvidedUser providedUser) {
            this.providedUser = providedUser;
        }

        @Override
        public ProvidedUser getProvidedUser() {
            return providedUser;
        }

        @Override
        public String getId() {
            return ID;
        }

        @Override
        public String getPwd() {
            return PWD;
        }

        @Override
        public Algorithm getAlgorithm() {
            return ALGORITHM;
        }
    }

    public static class TestProvidedUser implements ProvidedUser {

        private final String name;

        public TestProvidedUser(String name) {
            this.name = name;
        }

        @Override
        public Principal getPrincipal() {
            return new Principal() {
                @Override
                public String getName() {
                    return name;
                }
            };
        }

        @Override
        public boolean isInRole(String role) {
            return false;
        }
    }
}
