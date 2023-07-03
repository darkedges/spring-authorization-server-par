package darkedges;

import java.time.Instant;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;

/**
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class OAuth2RequestUri extends AbstractOAuth2Token {
	/**
	 * Constructs an {@code OAuth2RequestUri} using the provided parameters.
	 *
	 * @param tokenValue the token value
	 * @param issuedAt   the time at which the token was issued
	 * @param expiresAt  the time at which the token expires
	 */
	public OAuth2RequestUri(String tokenValue, Instant issuedAt, Instant expiresAt) {
		super(tokenValue, issuedAt, expiresAt);
	}
}
