package net.jalg.nioo.rs.server;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

/** A JAX-RS SecurityContext implementation suitable for use with Hawk.
 *
 * @author Jan Algermissen <algermissen@acm.org>
 */
public class HawkSecurityContext implements SecurityContext {

    private boolean isSecure;
    private ProvidedUser providedUser;

    /** Create a new security context using the specified TLS parameter and
     * a providedUser instance from which to get providedUser principal and providedUser-in-role
     * check.
     *
     * @param isSecure
     * @param providedUser
     */
    public HawkSecurityContext(boolean isSecure, ProvidedUser providedUser) {
        this.isSecure = isSecure;
        this.providedUser = providedUser;
    }

    @Override
    public Principal getUserPrincipal() {
        return providedUser.getPrincipal();
    }

    @Override
    public boolean isUserInRole(String role) {
        return providedUser.isInRole(role);
    }

    @Override
    public boolean isSecure() {
        return isSecure;
    }

    @Override
    public String getAuthenticationScheme() {
        return HawkFeature.SCHEME_NAME;
    }
}
