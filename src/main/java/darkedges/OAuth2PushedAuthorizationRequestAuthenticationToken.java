package darkedges;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation for the OAuth 2.0 Authorization
 * Request used in the Authorization Code Grant.
 *
 * @author Nicholas Irving
 * @see OAuth2PushedAuthorizationRequestAuthenticationProvider
 * @see OAuth2AuthorizationConsentAuthenticationProvider
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
	private final String authorizationUri;
	private RegisteredClient registeredClient;
	private final Authentication principal;
	private final String redirectUri;
	private final String state;
	private final Set<String> scopes;
	private final Map<String, Object> additionalParameters;
	private final OAuth2PushedAuthorizationRequest requestClaims;
	private OAuth2RequestUri oauth2RequestUri;

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationToken}
	 * using the provided parameters.
	 *
	 * @param authorizationUri     the authorization URI
	 * @param clientId             the client identifier
	 * @param registeredClient     the client registration
	 * @param redirectUri          the redirect uri
	 * @param state                the state
	 * @param scopes               the requested scope(s)
	 * @param additionalParameters the additional parameters
	 * @since 1.0.0
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationToken(String authorizationUri,
			RegisteredClient registeredClient, Authentication principal, @Nullable String redirectUri,
			@Nullable String state, @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.hasText(authorizationUri, "authorizationUri cannot be empty");
		Assert.notNull(registeredClient, "clientRegistration cannot be null");
		this.authorizationUri = authorizationUri;
		this.registeredClient = registeredClient;
		this.principal = principal;
		this.state = state;
		this.requestClaims = OAuth2PushedAuthorizationRequest.builder().build();
		this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
		this.additionalParameters = Collections.unmodifiableMap(
				additionalParameters != null ? new HashMap<>(additionalParameters) : Collections.emptyMap());
		this.redirectUri = redirectUri;
	}

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationToken}
	 * using the provided parameters.
	 *
	 * @param authorizationUri the authorization URI
	 * @param clientId         the client identifier
	 * @param principal        the {@code Principal} (Resource Owner)
	 * @param requestClaims    the {@link OAuth2PushedAuthorizationRequest}
	 * @param state            the state
	 * @param scopes           the authorized scope(s)
	 * @param requestUri
	 * @since 1.0.0
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationToken(String authorizationUri,
			RegisteredClient registeredClient, Authentication principal, OAuth2PushedAuthorizationRequest requestClaims,
			@Nullable String redirectUri, @Nullable String state, @Nullable Set<String> scopes,
			OAuth2RequestUri oauth2RequestUri) {
		super(Collections.emptyList());
		Assert.hasText(authorizationUri, "authorizationUri cannot be empty");
		Assert.notNull(registeredClient, "clientRegistration cannot be null");
		this.authorizationUri = authorizationUri;
		this.registeredClient = registeredClient;
		this.principal = principal;
		this.requestClaims = requestClaims;
		this.redirectUri = redirectUri;
		this.state = state;
		this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
		this.additionalParameters = Collections.emptyMap();
		this.oauth2RequestUri = oauth2RequestUri;
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		if(this.oauth2RequestUri!=null)
			return this.oauth2RequestUri.getTokenValue();
		else
			return "";
	}

	/**
	 * Returns the authorization URI.
	 *
	 * @return the authorization URI
	 */
	public String getAuthorizationUri() {
		return this.authorizationUri;
	}

	/**
	 * Returns the redirect uri.
	 *
	 * @return the redirect uri
	 */
	@Nullable
	public String getRedirectUri() {
		return this.redirectUri;
	}

	/**
	 * Returns the state.
	 *
	 * @return the state
	 */
	@Nullable
	public String getState() {
		return this.state;
	}

	/**
	 * Returns the requested (or authorized) scope(s).
	 *
	 * @return the requested (or authorized) scope(s), or an empty {@code Set} if
	 *         not available
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the additional parameters.
	 *
	 * @return the additional parameters, or an empty {@code Map} if not available
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns the {@link OAuth2PushedAuthorizationRequest}.
	 *
	 * @return the {@link OAuth2PushedAuthorizationRequest}
	 */
	public OAuth2PushedAuthorizationRequest getRequestClaims() {
		return this.requestClaims;
	}

	public RegisteredClient getRegisteredClient() {
		return this.registeredClient;
	}
}
