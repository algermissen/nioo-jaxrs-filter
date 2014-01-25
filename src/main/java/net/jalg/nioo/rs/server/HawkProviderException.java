package net.jalg.nioo.rs.server;

/** Exception thrown by HawkProvider implementations if some internal operations
 * (such as looking up credentials in a database) fail.
 *
 * @author Jan Algermissen <algermissen@acm.org>
 */
public class HawkProviderException extends Exception {

    /**
     *
     * @param message
     */
    public HawkProviderException(String message) {
        super(message);
    }

    /**
     *
     * @param message
     * @param cause
     */
    public HawkProviderException(String message, Throwable cause) {
        super(message, cause);
    }
}
