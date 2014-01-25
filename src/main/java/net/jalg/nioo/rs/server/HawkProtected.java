package net.jalg.nioo.rs.server;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


/**
 * Annotation for attaching a {@link HawkServerFilter} instance to a
 * JAX-RS resource method.
 *
 */
@Target({ ElementType.METHOD })
@Retention(value = RetentionPolicy.RUNTIME)
public @interface HawkProtected {

    /** This attribute specifies the realm the given resource method resides in.
     * It will be used in the 401 challenges.
     *
     * @return
     */
    String realm();

    /**
     * This attribute controls whether the filter should validate the request payload.
     *
     * @return
     */
    boolean validateRequestPayload();

    /**
     * This attribute controls whether the filter should add a response payload hash to the
     * Server-Authorization response header.
     * @return
     */
    boolean hashResponsePayload();

}