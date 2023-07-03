package darkedges;

import java.util.Set;
import java.util.function.Consumer;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Consumer} providing access to the
 * {@link OAuth2PushedAuthorizationRequestAuthenticationContext} containing an
 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken} and is the
 * default
 * {@link OAuth2PushedAuthorizationRequestAuthenticationProvider#setAuthenticationValidator(Consumer)
 * authentication validator} used for validating specific OAuth 2.0
 * Push Authorization Request parameters used in the Authorization Code Grant.
 *
 * <p>
 * The default implementation first validates
 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken#getRedirectUri()}
 * and then
 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken#getScopes()}. If
 * validation fails, an
 * {@link OAuth2PushedAuthorizationRequestAuthenticationException} is thrown.
 *
 * @author Joe Grandja
 * @see OAuth2PushedAuthorizationRequestAuthenticationContext
 * @see OAuth2PushedAuthorizationRequestAuthenticationToken
 * @see OAuth2PushedAuthorizationRequestAuthenticationProvider#setAuthenticationValidator(Consumer)
 * @since 0.4.0
 */
public class OAuth2PushedAuthorizationRequestAuthenticationValidator
		implements Consumer<OAuth2PushedAuthorizationRequestAuthenticationContext> {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
	/**
	 * The default validator for
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken#getScopes()}.
	 */
	public static final Consumer<OAuth2PushedAuthorizationRequestAuthenticationContext> DEFAULT_SCOPE_VALIDATOR = OAuth2PushedAuthorizationRequestAuthenticationValidator::validateScope;
	/**
	 * The default validator for
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken#getRedirectUri()}.
	 */
	public static final Consumer<OAuth2PushedAuthorizationRequestAuthenticationContext> DEFAULT_REDIRECT_URI_VALIDATOR = OAuth2PushedAuthorizationRequestAuthenticationValidator::validateRedirectUri;
	private final Consumer<OAuth2PushedAuthorizationRequestAuthenticationContext> authenticationValidator = DEFAULT_REDIRECT_URI_VALIDATOR
			.andThen(DEFAULT_SCOPE_VALIDATOR);

	private static void validateRedirectUri(
			OAuth2PushedAuthorizationRequestAuthenticationContext authenticationContext) {
		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthentication = authenticationContext
				.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();

		String requestedRedirectUri = pushedAuthorizationRequestAuthentication.getRedirectUri();
		if (StringUtils.hasText(requestedRedirectUri)) {
			// ***** redirect_uri is available in authorization request
			UriComponents requestedRedirect = null;
			try {
				requestedRedirect = UriComponentsBuilder.fromUriString(requestedRedirectUri).build();
			} catch (Exception ex) {
			}
			if (requestedRedirect == null || requestedRedirect.getFragment() != null) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
						pushedAuthorizationRequestAuthentication, registeredClient);
			}
			String requestedRedirectHost = requestedRedirect.getHost();
			if (requestedRedirectHost == null || requestedRedirectHost.equals("localhost")) {
				// As per
				// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07#section-9.7.1
				// While redirect URIs using localhost (i.e., "http://localhost:{port}/{path}")
				// function similarly to loopback IP redirects described in Section 10.3.3,
				// the use of "localhost" is NOT RECOMMENDED.
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
						"localhost is not allowed for the redirect_uri (" + requestedRedirectUri + "). "
								+ "Use the IP literal (127.0.0.1) instead.",
						"https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07#section-9.7.1");
				throwError(error, OAuth2ParameterNames.REDIRECT_URI, pushedAuthorizationRequestAuthentication,
						registeredClient);
			}

			if (!isLoopbackAddress(requestedRedirectHost)) {
				// As per
				// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07#section-9.7
				// When comparing client redirect URIs against pre-registered URIs,
				// authorization servers MUST utilize exact string matching.
				if (!registeredClient.getRedirectUris().contains(requestedRedirectUri)) {
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
							pushedAuthorizationRequestAuthentication, registeredClient);
				}
			} else {
				// As per
				// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07#section-10.3.3
				// The authorization server MUST allow any port to be specified at the
				// time of the request for loopback IP redirect URIs, to accommodate
				// clients that obtain an available ephemeral port from the operating
				// system at the time of the request.
				boolean validRedirectUri = false;
				for (String registeredRedirectUri : registeredClient.getRedirectUris()) {
					UriComponentsBuilder registeredRedirect = UriComponentsBuilder.fromUriString(registeredRedirectUri);
					registeredRedirect.port(requestedRedirect.getPort());
					if (registeredRedirect.build().toString().equals(requestedRedirect.toString())) {
						validRedirectUri = true;
						break;
					}
				}
				if (!validRedirectUri) {
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
							pushedAuthorizationRequestAuthentication, registeredClient);
				}
			}
		} else {
			// ***** redirect_uri is NOT available in authorization request
			if (pushedAuthorizationRequestAuthentication.getScopes().contains(OidcScopes.OPENID)
					|| registeredClient.getRedirectUris().size() != 1) {
				// redirect_uri is REQUIRED for OpenID Connect
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
						pushedAuthorizationRequestAuthentication, registeredClient);
			}
		}
	}

	private static void validateScope(OAuth2PushedAuthorizationRequestAuthenticationContext authenticationContext) {
		OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication = authenticationContext
				.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();

		Set<String> requestedScopes = PushedAuthorizationRequestAuthentication.getScopes();
		Set<String> allowedScopes = registeredClient.getScopes();
		if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
			throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE,
					PushedAuthorizationRequestAuthentication, registeredClient);
		}
	}

	private static boolean isLoopbackAddress(String host) {
		// IPv6 loopback address should either be "0:0:0:0:0:0:0:1" or "::1"
		if ("[0:0:0:0:0:0:0:1]".equals(host) || "[::1]".equals(host)) {
			return true;
		}
		// IPv4 loopback address ranges from 127.0.0.1 to 127.255.255.255
		String[] ipv4Octets = host.split("\\.");
		if (ipv4Octets.length != 4) {
			return false;
		}
		try {
			int[] address = new int[ipv4Octets.length];
			for (int i = 0; i < ipv4Octets.length; i++) {
				address[i] = Integer.parseInt(ipv4Octets[i]);
			}
			return address[0] == 127 && address[1] >= 0 && address[1] <= 255 && address[2] >= 0 && address[2] <= 255
					&& address[3] >= 1 && address[3] <= 255;
		} catch (NumberFormatException ex) {
			return false;
		}
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication,
			RegisteredClient registeredClient) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI);
		throwError(error, parameterName, PushedAuthorizationRequestAuthentication, registeredClient);
	}

	private static void throwError(OAuth2Error error, String parameterName,
			OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication,
			RegisteredClient registeredClient) {

		String redirectUri = StringUtils.hasText(PushedAuthorizationRequestAuthentication.getRedirectUri())
				? PushedAuthorizationRequestAuthentication.getRedirectUri()
				: registeredClient.getRedirectUris().iterator().next();
		if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST)
				&& parameterName.equals(OAuth2ParameterNames.REDIRECT_URI)) {
			redirectUri = null; // Prevent redirects
		}

		OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthenticationResult = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				PushedAuthorizationRequestAuthentication.getAuthorizationUri(),
				PushedAuthorizationRequestAuthentication.getRegisteredClient(),
				(Authentication) PushedAuthorizationRequestAuthentication.getPrincipal(), redirectUri,
				PushedAuthorizationRequestAuthentication.getState(),
				PushedAuthorizationRequestAuthentication.getScopes(),
				PushedAuthorizationRequestAuthentication.getAdditionalParameters());
		PushedAuthorizationRequestAuthenticationResult.setAuthenticated(true);

		throw new OAuth2PushedAuthorizationRequestAuthenticationException(error,
				PushedAuthorizationRequestAuthenticationResult);
	}

	@Override
	public void accept(OAuth2PushedAuthorizationRequestAuthenticationContext authenticationContext) {
		this.authenticationValidator.accept(authenticationContext);
	}
}
