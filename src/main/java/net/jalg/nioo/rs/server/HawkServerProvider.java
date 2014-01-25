package net.jalg.nioo.rs.server;

public interface HawkServerProvider {

    /**
     * Get an optionally configured validation port.
     *
     * @return Configured validation port or -1 if none has been configured.
     */
    public int getConfiguredValidationPort();

    /**
     * Get an optionally configured validation host.
     *
     * @return Configured validation host or null if none has been configured.
     */
    public String getConfiguredValidationHost();

    /**
     * Get the configured allowed clock skew. Returning a 0 here turns
     * clock skew checking off.
     *
     * @return The allowed clock skew or 0 to turn off clock skew checking.
     */
    public int getAllowedClockSkew();

    /**
     * Lookup the Hawk credentials for a given ID.
     * <p>
     *    If the credentials could not be found then return null. If an error occurred
     *    during the lookup then an exception will be thrown.
     * </p>
     *
     * @param id The id of the credentials to look up
     * @return HawkCredentials belonging to the given ID or null if no credentials for this ID have been found.
     * @throws HawkProviderException
     */
    public HawkCredentials getHawkCredentials(String id) throws HawkProviderException;

    /** Note a used nonce with the provider.
     *
     * The provider can store the nonce to prevent its recurring use within the configured
     * clock skew.
     *
     * @param id
     * @param ts
     * @param nonce
     */
    public void noteNonce(String id, long ts, String nonce);
    /**
     * Check whether the provided nonce is valid (has not been used before).
     *
     * @param id Hawk ID this nonce has been used with
     * @param ts Timestamp of when the nonce was used.
     * @param nonce the nonce
     * @return return true if this nonce has not been used before.
     */
    public boolean nonceHasBeenUsedBefore(String id, long ts, String nonce) throws HawkProviderException;

}
