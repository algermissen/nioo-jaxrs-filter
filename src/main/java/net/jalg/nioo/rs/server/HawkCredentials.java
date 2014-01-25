package net.jalg.nioo.rs.server;

import net.jalg.hawkj.Algorithm;

/** Credentials for Hawk authentication.
 *
 *
 * @author Jan Algermissen <algermissen@acm.org>
 */
public interface HawkCredentials {

    /**
     *
     * @return
     */
    public String getId();

    /**
     *
     * @return
     */
    public String getPwd();

    /**
     *
     * @return
     */
    public Algorithm getAlgorithm();

    /**
     *
     * @return
     */
    public ProvidedUser getProvidedUser();

}
