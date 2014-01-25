package net.jalg.nioo.rs.server;

import net.jalg.hawkj.*;
import net.jalg.hawkj.HawkContext.HawkContextBuilder;
import net.jalg.hawkj.ext.InputStreamBuffer;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.ReaderInterceptor;
import javax.ws.rs.ext.ReaderInterceptorContext;
import javax.ws.rs.ext.WriterInterceptor;
import javax.ws.rs.ext.WriterInterceptorContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Server side filter and interceptor for adding and validating Hawk HTTP
 * Authentication.
 * <p/>
 *
 * @author Jan Algermissen, http://jalg.net
 */
@Priority(Priorities.AUTHENTICATION)
public class HawkServerFilter implements ContainerRequestFilter,
        ContainerResponseFilter, ReaderInterceptor, WriterInterceptor {

    private static final int HTTP_DEFAULT_PORT = 80;

    private static final int HTTPS_DEFAULT_PORT = 443;

    public static final String HAWK_SERVER_PROPERTY = "net.jalg.nioo.rs.server.hawk";


    private static Logger LOG = Logger.getLogger(HawkServerFilter.class
            .getName());

    private HawkServerProvider hawkProvider;

    private String realm;

    private final boolean validateRequestPayload;

    private final boolean hashResponsePayload;

    @Context
    private Request request;

    @Context
    private UriInfo uriInfo;


    /**
     * Create a new instance of the Hawk server filter.
     *
     * The 401 challenge will not include a realm.
     *
     * @param hawkProvider
     * @param validateRequestPayload
     * @param hashResponsePayload
     */
    public HawkServerFilter(HawkServerProvider hawkProvider,
                            boolean validateRequestPayload, boolean hashResponsePayload) {
        this(hawkProvider,null,validateRequestPayload,hashResponsePayload);
    }

    /**
     * Create a new instance of the Hawk server filter with a specific realm.
     *
     * The provided realm will be used in 401 responses as part of the
     * challenge.
     *
     * @param hawkProvider
     * @param realm
     * @param validateRequestPayload
     * @param hashResponsePayload
     */
    public HawkServerFilter(HawkServerProvider hawkProvider, String realm,
                            boolean validateRequestPayload, boolean hashResponsePayload) {
        this.realm = realm;
        this.hawkProvider = hawkProvider;
        this.validateRequestPayload = validateRequestPayload;
        this.hashResponsePayload = hashResponsePayload;
    }

    private Response createDefault401Response() {
        String value = HawkContext.SCHEME;
        if(realm != null) {
            value += " realm=\"" + realm + "\"";
        }

        return Response.status(Status.UNAUTHORIZED)

                .header(HttpHeaders.WWW_AUTHENTICATE, value)
                .type("text/plain").entity("Unable to authorize request.")
                .build();
    }

    private Response create401Response(HawkWwwAuthenticateContext context) {
        WwwAuthenticateHeader header = context.createWwwAuthenticateHeader();
        return Response.status(Status.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, header.toString())
                .type("text/plain").entity("Unable to authorize request.")
                .build();
    }

    private Response create500Response() {
        return Response.status(Status.INTERNAL_SERVER_ERROR)
                .type("text/plain").entity("Internal Server Error")
                .build();
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * javax.ws.rs.container.ContainerRequestFilter#filter(javax.ws.rs.container
     * .ContainerRequestContext)
     */
    @Override
    public void filter(final ContainerRequestContext requestContext)
            throws IOException {
        /*
         * Since we are protecting a resource, we require the authorization
		 * header.
		 */
        if (!requestContext.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            requestContext.abortWith(createDefault401Response());
            return;
        }

		/*
		 * Parse Authorization header.
		 */
        AuthorizationHeader authHeader;
        try {
            authHeader = AuthorizationHeader.authorization(requestContext
                    .getHeaderString(HttpHeaders.AUTHORIZATION));
        } catch (AuthHeaderParsingException e) {
            LOG.log(Level.SEVERE, "Unable to parse HTTP Authorization header, {0}", e);
            requestContext.abortWith(createDefault401Response());
            return;
        }

        /*
         * Look up the Hawk credentials for the given ID.
         */
        HawkCredentials credentials = null;
        try {
            credentials = hawkProvider.getHawkCredentials(realm,authHeader.getId());
        } catch (HawkProviderException e) {
            LOG.log(Level.SEVERE, "Unable to get hawk credentials for Hawk ID: " + authHeader.getId(), e);
            requestContext.abortWith(create500Response());
            return;
        }
        /*
         * Credentials for ID not found, meaning ID is unknown.
         */
        if (credentials == null) {
            requestContext.abortWith(createDefault401Response());
            return;
        }
        String id = authHeader.getId();
        String password = credentials.getPwd();
        Algorithm algorithm = credentials.getAlgorithm();

		/*
		 * Create request Hawk from request data and parsed header. Note:
		 * Builder interface is designed to work with null-ext and null-hash, so
		 * we do not need conditionals here.
		 */
        int port = determineValidationPort(requestContext, hawkProvider);
        String host = determineValidationHost(requestContext, hawkProvider);
        HawkContext hawk = HawkContext
                .request(requestContext.getMethod(), requestContext.getUriInfo().getRequestUri().getPath(),
                        host, port)
                .credentials(id, password, algorithm)
                .tsAndNonce(authHeader.getTs(), authHeader.getNonce())
                .hash(authHeader.getHash()).build();

		/*
		 * Now we use the created Hawk to validate the HMAC sent by the client
		 * in the Authorization header.
		 */
        if (!hawk.isValidMac(authHeader.getMac())) {
            LOG.log(Level.WARNING, "Invalid Hawk signature for ID {0} ", authHeader.getId());
            requestContext.abortWith(createDefault401Response());
            return;
        }

		/*
		 * Check timestamp. If the skew is too large we abort with a 401
		 * response, giving the client our current time.
		 */
        int now = (int) (System.currentTimeMillis() / 1000L);
        int allowedSkew = hawkProvider.getAllowedClockSkew();

        if ((allowedSkew != 0) && (hawk.getTs() < now - allowedSkew) || (hawk.getTs() > now + allowedSkew)) {
            LOG.log(Level.FINE, "Clock skew too large. Now: {0}, ts: {1}",
                    new String[]{String.valueOf(now), String.valueOf(hawk.getTs())});
            HawkWwwAuthenticateContext c = HawkWwwAuthenticateContext.ts()
                    .credentials(id, password, algorithm).build();
            requestContext.abortWith(create401Response(c));
            return;
        }

		/*
		 * Check nonce to prevent replay attacks.
		 */
        try {
            if (hawkProvider.nonceHasBeenUsedBefore(id, hawk.getTs(), hawk.getNonce())) {
                LOG.log(Level.FINE,
                        "Possible replay attack - nonce has been used before for ID: {0}, TS: {1}, Nonce: {2}",
                        new String[]{id, String.valueOf(hawk.getTs()),
                                hawk.getNonce()});
                requestContext.abortWith(createDefault401Response());
                return;
            }
        } catch (HawkProviderException e) {
            LOG.log(Level.SEVERE, "Unable to validate nonce", e);
            requestContext.abortWith(create500Response());
            return;
        }

        /*
         * Hand nonce to provider in case it wants to remember and do nonce checking.
         */
        hawkProvider.noteNonce(id, hawk.getTs(), hawk.getNonce());


		/*
		 * Now that the client has been authenticated, we can make the security
		 * context available to the request chain.
		 */
        requestContext.setSecurityContext(new HawkSecurityContext(requestContext.getSecurityContext().isSecure(), credentials.getProvidedUser()));

		/*
		 * Store request Hawk in context for reader interceptor to optionally
		 * verify payload hash and also so that the response chain can access
		 * the request information when (optionally) calculating the response
		 * Server-Authorization header.
		 */
        requestContext.setProperty(HAWK_SERVER_PROPERTY, hawk);
    }

    /*
     * (non-Javadoc)
     *
     * @see javax.ws.rs.ext.ReaderInterceptor#aroundReadFrom(javax.ws.rs.ext.
     * ReaderInterceptorContext)
     */
    @Override
    public Object aroundReadFrom(ReaderInterceptorContext context)
            throws IOException, WebApplicationException {
		/*
		 * If we are not configured to enforce payload validatio, we can pass
		 * here.
		 */
        if (!this.validateRequestPayload) {
            return context.proceed();
        }

		/*
		 * Obtain request Hawk to get access to request data.
		 */
        HawkContext requestHawk = (HawkContext) context.getProperty(HAWK_SERVER_PROPERTY);
        if (requestHawk == null) {
            LOG.log(Level.SEVERE, "Did not find HawkContext in request properties. This is unexpected an maybe indicates some filters messed up the properties");
            throw new WebApplicationException(Status.INTERNAL_SERVER_ERROR);
        }

        /*
         * The annotation configured the current resource method to require a body has in the request.
         * We deny access here if the client does not send that header.
         */
        if (!requestHawk.hasHash()) {
            LOG.log(Level.FINE, "No payload hash in Authorization request header but configuration requires it");
            throw new WebApplicationException(createDefault401Response());
        }

		/*
		 * Hook buffering input stream into the reading chain and read the
		 * entity. A copy of the data will be placed in the buffer. This buffer
		 * is the used to calculate the hast.
		 * https://github.com/algermissen/nioo-jaxrs-filter/issues/3
		 */
        InputStream old = context.getInputStream();
        InputStreamBuffer streamBuffer = new InputStreamBuffer(old);
        context.setInputStream(streamBuffer);
        Object entity = context.proceed();
        byte[] body = streamBuffer.getBuffer();

        String hash = HawkContextBuilder.generateHash(requestHawk
                .getAlgorithm(), body, context.getMediaType().toString());
		/*
		 * Compare calculated hash to the hash we received in the Authorization
		 * header.
		 */
        if (!Util.fixedTimeEqual(hash, requestHawk.getHash())) {
            LOG.log(Level.SEVERE, "Payload hashes do not match");
            throw new WebApplicationException(createDefault401Response());
        }
        return entity;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * javax.ws.rs.container.ContainerResponseFilter#filter(javax.ws.rs.container
     * .ContainerRequestContext, javax.ws.rs.container.ContainerResponseContext)
     */
    @Override
    public void filter(final ContainerRequestContext requestContext,
                       ContainerResponseContext responseContext) throws IOException {
		/*
		 * Removing the Hawk from the context properties signals
		 * WriterInterceptor to not add a Server-Authorization header for
		 * response payload validation.
		 */
        if (responseContext.getStatusInfo().getFamily() != Status.Family.SUCCESSFUL) {
            requestContext.removeProperty(HAWK_SERVER_PROPERTY);
        }
        /*
		 * Skip response payload hashing if configuration says so. In this case,
		 * we also do not include a Server-Authorization header because that
		 * make not much sense. But see also
		 * https://github.com/algermissen/nioo-jaxrs-filter/issues/1
		 * https://github.com/algermissen/nioo-jaxrs-filter/issues/2
		 */
        if (!this.hashResponsePayload) {
            requestContext.removeProperty(HAWK_SERVER_PROPERTY);
            return;
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see javax.ws.rs.ext.WriterInterceptor#aroundWriteTo(javax.ws.rs.ext.
     * WriterInterceptorContext)
     */
    @Override
    public void aroundWriteTo(WriterInterceptorContext context)
            throws IOException, WebApplicationException {
		/*
		 * Missing request Hawk in context is used to signal to us to skip
		 * processing.  For example for non 2xx responses. But see also
		 * https://github.com/algermissen/nioo-jaxrs-filter/issues/1
		 */
        HawkContext requestHawk = (HawkContext) context.getProperty(HAWK_SERVER_PROPERTY);
        if (requestHawk == null) {
            context.proceed();
            return;
        }

		/*
		 * Buffer output stream to calculate hash.
		 * https://github.com/algermissen/nioo-jaxrs-filter/issues/3
		 */
        OutputStream old = context.getOutputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        context.setOutputStream(baos);
        context.proceed();

        final byte[] body = baos.toByteArray();

		/*
		 * Make a clone of the request Hawk, add the hash value and construct
		 * Server-Authorization header from it.
		 */
        HawkContext responseHawk = requestHawk.cloneC()
                .body(body, context.getMediaType().toString()).build();
        context.getHeaders().add(HawkContext.SERVER_AUTHORIZATION,
                responseHawk.createAuthorizationHeader().toString());
        old.write(body);
    }

    /**
     * Determine the port to use for validating the HMAC signature.
     *
     * @param requestContext
     * @return A valid port number to use for validation
     */
    private static int determineValidationPort(ContainerRequestContext requestContext, HawkServerProvider hawkServerProvider) {

        int port = hawkServerProvider.getConfiguredValidationPort();
        if (port >= 0) {
            return port;
        }
        port = requestContext.getUriInfo().getRequestUri().getPort();
        if (port < 0) {
            if (requestContext.getSecurityContext().isSecure()) {
                port = HTTPS_DEFAULT_PORT;
            } else {
                port = HTTP_DEFAULT_PORT;
            }
        }
        return port;
    }

    /**
     * Determine the host to use for validating the HMAC signature.
     *
     * @param requestContext
     * @return a hostname to use for validation.
     */
    private static String determineValidationHost(ContainerRequestContext requestContext, HawkServerProvider hawkServerProvider) {

        String host = hawkServerProvider.getConfiguredValidationHost();
        if (host != null) {
            return host;
        }
        return requestContext.getUriInfo().getRequestUri().getHost();
    }


}
