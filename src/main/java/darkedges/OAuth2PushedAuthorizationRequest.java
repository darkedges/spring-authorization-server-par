package darkedges;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimAccessor;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

/**
 * A representation of the claims returned in an OAuth 2.0 Token Introspection
 * Response.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 * @see OAuth2TokenIntrospectionClaimAccessor
 * @see <a target="_blank" href=
 *      "https://tools.ietf.org/html/rfc7662#section-2.2">Section 2.2
 *      Introspection Response</a>
 * @since 0.1.1
 */
public final class OAuth2PushedAuthorizationRequest implements OAuth2TokenIntrospectionClaimAccessor, Serializable {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
	private final Map<String, Object> claims;

	private OAuth2PushedAuthorizationRequest(Map<String, Object> claims) {
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Constructs a new {@link Builder} initialized with the {@link #isActive()
	 * active} claim to {@code false}.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Constructs a new {@link Builder} initialized with the provided claims.
	 *
	 * @param claims the claims to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder withClaims(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		return builder().claims(c -> c.putAll(claims));
	}

	/**
	 * Returns the claims in the Token Introspection Response.
	 *
	 * @return a {@code Map} of the claims
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	public Instant getExpiresIn() {
		return getClaimAsInstant(OAuth2PushedAuthorizationRequestClaimNames.EXPIRES_IN);
	}

	/**
	 * A builder for {@link OAuth2TokenIntrospection}.
	 */
	public static class Builder {
		private final Map<String, Object> claims = new LinkedHashMap<>();

		/**
		 * Sets the client identifier for the OAuth 2.0 client that requested this
		 * token, REQUIRED.
		 *
		 * @param requestUri the client identifier for the OAuth 2.0 client that
		 *                   requested this token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder requestUri(String requestUri) {
			return claim(OAuth2PushedAuthorizationRequestClaimNames.REQUEST_URI, requestUri);
		}

		/**
		 * Sets the time indicating when this token will expire, REQUIRED.
		 *
		 * @param expiresIn the time indicating when this token will expire
		 * @return the {@link Builder} for further configuration
		 */
		public Builder expiresIn(int expiresIn) {
			return claim(OAuth2PushedAuthorizationRequestClaimNames.EXPIRES_IN, expiresIn);
		}

		/**
		 * Sets the claim.
		 *
		 * @param name  the claim name
		 * @param value the claim value
		 * @return the {@link Builder} for further configuration
		 */
		public Builder claim(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 *
		 * @param claimsConsumer a {@code Consumer} of the claims
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Validate the claims and build the {@link OAuth2TokenIntrospection}.
		 * <p>
		 * The following claims are REQUIRED: {@code active}
		 *
		 * @return the {@link OAuth2TokenIntrospection}
		 */
		public OAuth2PushedAuthorizationRequest build() {
			validate();
			return new OAuth2PushedAuthorizationRequest(this.claims);
		}

		private void validate() {
			if (this.claims.containsKey(OAuth2PushedAuthorizationRequestClaimNames.REQUEST_URI)) {
				Assert.notNull(this.claims.get(OAuth2PushedAuthorizationRequestClaimNames.REQUEST_URI),
						"redirect_uri cannot be null");
			}
			if (this.claims.containsKey(OAuth2PushedAuthorizationRequestClaimNames.EXPIRES_IN)) {
				Assert.isInstanceOf(Integer.class,
						this.claims.get(OAuth2PushedAuthorizationRequestClaimNames.EXPIRES_IN),
						"expires_in must be of type Instant");
			}
		}
	}
}
