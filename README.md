nioo-jaxrs-filter
=================

JAX-RS 2 Filter for Hawk-based access delegation.

JAX-RS 2 resource methods are protected by attaching the @HawkProtected annotation:

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @HawkProtected(realm="test", validateRequestPayload = false,hashResponsePayload = true)
    public String get(@Context SecurityContext sc) {

        Principal p = sc.getUserPrincipal();

        return "This response body will be hashed and added to " +
               "the Server-Authorization response header";
    }


Note how the injected SecurityContext provides access to the Hawk ID.




Implementing HawkProvider
=========================

The filter requires an instance of an implementation of the HawkProvider interface.
This HawkProvider instance provides the filter with access to the credentials,
nonce checking and configuration options.


     public static class MyProvider implements HawkServerProvider {

        @Override
        public int getConfiguredValidationPort() {
            return -1; // No override port configured
        }

        @Override
        public String getConfiguredValidationHost() {
            return null; // No override host configured
        }

        @Override
        public HawkCredentials getHawkCredentials(String realm, String id) throws HawkProviderException {
            // (Maybe pick identity store based on realm)
            Identity identity = identityService.lookupIdentity(id);
            return new MyCredentials(identity));
        }

        @Override
        public void noteNonce(String id, long ts, String nonce) {
            // store nonce for ID and time of use in some storage
            ...
        }

        @Override
        public boolean nonceHasBeenUsedBefore(String id, long ts, String nonce) throws HawkProviderException {
            boolean usedBefore;
            // check in some storage whether nonce has beedn used before
            ...
            return usedBefore;
        }

        @Override
        public int getAllowedClockSkew() {
            return 10; // Allow 20 seconds of clock skew (10 more, 10 less)
        }
    }


Setting Up The Filter
=====================

To set up the filter you need to register the feature with the JAX-RS runtime. How this is done
is implementations specific; below you see an example using Jersey 2.

    MyProvider hawkProvider = new MyProvider( ... some database hook maybe ... );
    HawkFeature hawkFeature = new HawkFeature(hawkProvider);
    final ResourceConfig rc = new ResourceConfig().packages(... your JAX-RS resource packages ...)
            .register(hawkFeature);


The HawkProvider implementations is instantiated with the appropriate connection to the
given environment (where the configuration is, where the credentials are stored, etc) and passed to
the HawkFeature constructor. The feature is then registered with the JAX-RS runtime.

During runtime startup the feature will attach the Hawk filter to all Resource methods that
have the @HawkProtected annotation present.


Protecting a Resource
=====================

In order to protect a resource method with the Hawk filter, simply put the annotation to that
resource and configure the body validation and hashing parameters:


    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @HawkProtected(realm="test",validateRequestPayload = false,hashResponsePayload = true)
    public String get() {
        return "This response body will be hashed and added to " +
               "the Server-Authorization response header";
    }


    @POST
    @Produces(MediaType.TEXT_PLAIN)
    @HawkProtected(realm="test",validateRequestPayload = true,hashResponsePayload = false)
    public String post(@Context SecurityContext sc, String body) {

        // the filter will have verified that body has not been tampered with
        return "Hello";
    }









