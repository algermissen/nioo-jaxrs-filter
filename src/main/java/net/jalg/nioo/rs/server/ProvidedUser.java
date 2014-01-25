package net.jalg.nioo.rs.server;

import java.security.Principal;

/** User provided by HawkProvider.
 *
 * This interface is used by HawkProvider implementations to supply principal and
 * role information as part of the credentials lookup.
 *
 * @author Jan Algermissen <algermissen@acm.org>
 */
public interface ProvidedUser {

    public Principal getPrincipal();

    public boolean isInRole(String role);

}
