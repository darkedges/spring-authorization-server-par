package darkedges;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * This exception is thrown by {@link OAuth2PushedAuthorizationRequestAuthenticationProvider}
 * when an attempt to authenticate the OAuth 2.0 Authorization Request (or Consent) fails.
 *
 * @author Nicholas Irving
 * @see OAuth2PushedAuthorizationRequestAuthenticationToken
 * @see OAuth2PushedAuthorizationRequestAuthenticationProvider
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestAuthenticationException extends OAuth2AuthenticationException {
	private final OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication;

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationException} using the provided parameters.
	 *
	 * @param error                                    the {@link OAuth2Error OAuth 2.0 Error}
	 * @param PushedAuthorizationRequestAuthentication the {@link Authentication} instance of the OAuth 2.0 Authorization Request (or Consent)
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationException(OAuth2Error error,
			@Nullable OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication) {
		super(error);
		this.PushedAuthorizationRequestAuthentication = PushedAuthorizationRequestAuthentication;
	}

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationException} using the provided parameters.
	 *
	 * @param error                                    the {@link OAuth2Error OAuth 2.0 Error}
	 * @param cause                                    the root cause
	 * @param PushedAuthorizationRequestAuthentication the {@link Authentication} instance of the OAuth 2.0 Authorization Request (or Consent)
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationException(OAuth2Error error, Throwable cause,
			@Nullable OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication) {
		super(error, cause);
		this.PushedAuthorizationRequestAuthentication = PushedAuthorizationRequestAuthentication;
	}

	/**
	 * Returns the {@link Authentication} instance of the OAuth 2.0 Authorization Request (or Consent), or {@code null} if not available.
	 *
	 * @return the {@link OAuth2PushedAuthorizationRequestAuthenticationToken}
	 */
	@Nullable
	public OAuth2PushedAuthorizationRequestAuthenticationToken getPushedAuthorizationRequestAuthentication() {
		return this.PushedAuthorizationRequestAuthentication;
	}
}

