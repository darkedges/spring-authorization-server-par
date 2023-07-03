package darkedges;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationContext;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken} and additional
 * information and is used when validating the OAuth 2.0 Pushed Authorization
 * Request used in the Authorization Code Grant.
 *
 * @author Nicholas Irving
 * @see OAuth2AuthenticationContext
 * @see OAuth2PushedAuthorizationRequestAuthenticationToken
 * @see OAuth2PushedAuthorizationRequestAuthenticationProvider#setAuthenticationValidator(Consumer)
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestAuthenticationContext implements OAuth2AuthenticationContext {
	private final Map<Object, Object> context;

	private OAuth2PushedAuthorizationRequestAuthenticationContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	/**
	 * Constructs a new
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationContext.Builder} with
	 * the provided {@link OAuth2PushedAuthorizationRequestAuthenticationToken}.
	 *
	 * @param authentication the
	 *                       {@link OAuth2PushedAuthorizationRequestAuthenticationToken}
	 * @return the
	 *         {@link OAuth2PushedAuthorizationRequestAuthenticationContext.Builder}
	 */
	public static OAuth2PushedAuthorizationRequestAuthenticationContext.Builder with(
			OAuth2PushedAuthorizationRequestAuthenticationToken authentication) {
		return new OAuth2PushedAuthorizationRequestAuthenticationContext.Builder(authentication);
	}

	@SuppressWarnings("unchecked")
	@Nullable
	@Override
	public <V> V get(Object key) {
		return hasKey(key) ? (V) this.context.get(key) : null;
	}

	@Override
	public boolean hasKey(Object key) {
		Assert.notNull(key, "key cannot be null");
		return this.context.containsKey(key);
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 *
	 * @return the {@link RegisteredClient}
	 */
	public RegisteredClient getRegisteredClient() {
		return get(RegisteredClient.class);
	}

	/**
	 * A builder for {@link OAuth2PushedAuthorizationRequestAuthenticationContext}.
	 */
	public static final class Builder extends
			AbstractBuilder<OAuth2PushedAuthorizationRequestAuthenticationContext, OAuth2PushedAuthorizationRequestAuthenticationContext.Builder> {

		private Builder(OAuth2PushedAuthorizationRequestAuthenticationToken authentication) {
			super(authentication);
		}

		/**
		 * Sets the {@link RegisteredClient registered client}.
		 *
		 * @param registeredClient the {@link RegisteredClient}
		 * @return the
		 *         {@link OAuth2PushedAuthorizationRequestAuthenticationContext.Builder}
		 *         for further configuration
		 */
		public OAuth2PushedAuthorizationRequestAuthenticationContext.Builder registeredClient(
				RegisteredClient registeredClient) {
			return put(RegisteredClient.class, registeredClient);
		}

		/**
		 * Builds a new {@link OAuth2PushedAuthorizationRequestAuthenticationContext}.
		 *
		 * @return the {@link OAuth2PushedAuthorizationRequestAuthenticationContext}
		 */
		public OAuth2PushedAuthorizationRequestAuthenticationContext build() {
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			return new OAuth2PushedAuthorizationRequestAuthenticationContext(getContext());
		}

	}
}
