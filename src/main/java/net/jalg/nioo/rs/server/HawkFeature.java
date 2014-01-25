package net.jalg.nioo.rs.server;


import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.lang.annotation.Annotation;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * JAX-RS DynamicFeature implementation for registering Hawk container filter.
 *
 * HawkFeature needs to be explicitly registered because it needs to be passed a
 * HawkProvider instance for credentials and nonce lookup etc.
 * <p>
 * The specific resource methods that are to be protected using Hawk and the individual
 * per-method configuration needs to be specified by attaching a @HawkProtected annotation
 * to the desired methods.
 * <p>
 *
 * @author Jan Algermissen, http://jalg.net
 *
 */
public class HawkFeature implements DynamicFeature {

    public static final String SCHEME_NAME = "Hawk";

	private HawkServerProvider hawkProvider;

	/**
	 * Create a new HawkFeature using the given HawkProvider instance.
     * This method is responsible for bootstrapping; it binds the filter instances
     * to the application specific HawkProvider which is responsible for
     * providing credentials, nonce-checking, configuration etc.
	 *
	 * @param hawkProvider
	 */
	public HawkFeature(HawkServerProvider hawkProvider) {
		this.hawkProvider = hawkProvider;
	}

	@Override
	public void configure(ResourceInfo ri, FeatureContext fc) {

		/*
		 * Register Hawk Filter if @HawkProtected is present.
		 */

		for (Annotation annotation : ri.getResourceMethod().getAnnotations()) {
			if (annotation.annotationType() == HawkProtected.class) {

				HawkProtected hp = (HawkProtected) annotation;
                String realm = hp.realm();
				boolean validateRequestPayload = hp.validateRequestPayload();
				boolean hashResponsePayload = hp.hashResponsePayload();

				fc.register(new HawkServerFilter(hawkProvider, realm,
						validateRequestPayload, hashResponsePayload));
			}
		}

	}

}
