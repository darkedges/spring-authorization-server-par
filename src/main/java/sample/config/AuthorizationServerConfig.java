/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import java.util.Arrays;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2PushedAuthorizationRequestEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import sample.jose.Jwks;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		//OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();
		RequestMatcher endpointsMatcher1 = authorizationServerConfigurer
				.getEndpointsMatcher();
		OAuth2PushedAuthorizationRequestEndpointConfigurer pushedAuthorizationRequestEndpointConfigurer =
				new OAuth2PushedAuthorizationRequestEndpointConfigurer();
		RequestMatcher endpointsMatcher2 = pushedAuthorizationRequestEndpointConfigurer
				.getEndpointsMatcher();
		
		RequestMatcher endpointsMatcher = new OrRequestMatcher(endpointsMatcher1,endpointsMatcher2);
				http
			.securityMatcher(endpointsMatcher)
			.authorizeHttpRequests(authorize ->
				authorize.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.apply(authorizationServerConfigurer);
		
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0
		http.apply(pushedAuthorizationRequestEndpointConfigurer);
		
		// TODO Configure pushedAuthorizationRequestEndpointConfigurer

		// @formatter:off
		http
			.exceptionHandling(exceptions ->
				exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			)
			.oauth2ResourceServer(oauth2ResourceServer ->
			oauth2ResourceServer.jwt(Customizer.withDefaults()));
		// @formatter:on
		return http.build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		String jwkSetUri = "http://127.0.0.1:9000/resources";
		ClientSettings clientSettings = ClientSettings.builder().requireProofKey(false)
				.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.ES256).jwkSetUrl(jwkSetUri).build();
		TokenSettings tokenSettings = TokenSettings.builder().idTokenSignatureAlgorithm(SignatureAlgorithm.ES256)
				.build();
		RegisteredClient registeredClient1 = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("a9fa0032-2177-4f7b-aae2-d2f7df486d99").clientSecret("")
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("https://www.certification.openid.net/test/a/darkedges/callback").scope(OidcScopes.OPENID)
				.scope(OidcScopes.OPENID).clientSettings(clientSettings).tokenSettings(tokenSettings).build();
		RegisteredClient registeredClient2 = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("95efe06f-5e05-4d3c-b9a9-eabb49d054de").clientSecret("")
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("https://www.certification.openid.net/test/a/darkedges/callback").scope(OidcScopes.OPENID)
				.scope(OidcScopes.OPENID).clientSettings(clientSettings).tokenSettings(tokenSettings).build();

		return new InMemoryRegisteredClientRepository(registeredClient1, registeredClient2);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		ECKey ecKey = Jwks.generateEc();
		JWKSet jwkSet = new JWKSet(Arrays.asList(rsaKey, ecKey));
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

}
