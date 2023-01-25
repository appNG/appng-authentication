package org.appng.application.authentication.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.model.Application;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.coveo.saml.SamlClient;
import com.coveo.saml.SamlException;
import com.coveo.saml.SamlResponse;

import lombok.extern.slf4j.Slf4j;

/**
 * <a href= "https://learn.microsoft.com/de-de/azure/active-directory/fundamentals/auth-saml"><img alt="SAML Auth" src=
 * "https://learn.microsoft.com/de-de/azure/active-directory/fundamentals/media/authentication-patterns/saml-auth.png"
 * /></a>
 */
@Slf4j
@RestController
@SuppressWarnings("unchecked")
public class SamlController implements InitializingBean {

	@SuppressWarnings("rawtypes")
	private static final ResponseEntity NOT_IMPLEMENTED = ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).build();

	private @Autowired Application application;

	private @Value("${samlEnabled:false}") boolean samlEnabled;
	private @Value("${samlClientId:}") String clientId;
	private @Value("${samlAssertionConsumerUrl:}") String assertionConsumerUrl;
	private SamlClient samlClient;

	@Override
	public void afterPropertiesSet() throws Exception {
		if (samlEnabled) {
			byte[] samlDescriptor = application.getProperties().getClob("samlDescriptor")
					.getBytes(StandardCharsets.UTF_8);
			samlClient = SamlClient.fromMetadata(clientId, assertionConsumerUrl,
					new InputStreamReader(new ByteArrayInputStream(samlDescriptor)), SamlClient.SamlIdpBinding.POST);
		}
	}

	@GetMapping(path = "/saml/login", produces = MediaType.TEXT_HTML_VALUE)
	public void login(HttpServletResponse response) throws IOException, SamlException {
		if (!samlEnabled) {
			response.setStatus(NOT_IMPLEMENTED.getStatusCodeValue());
			return;
		}
		samlClient.redirectToIdentityProvider(response, null);
	}

	@PostMapping(path = "/saml/sign-on", produces = { MediaType.TEXT_PLAIN_VALUE }, consumes = {
			MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<String> signOn(@RequestBody String payload) {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

	@GetMapping(path = "/saml/sign-on", produces = { MediaType.TEXT_PLAIN_VALUE })
	public ResponseEntity<String> signOn() {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@PostMapping(path = "/saml/logout", produces = { MediaType.TEXT_PLAIN_VALUE }, consumes = {
			MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<String> logout(@RequestBody String payload) {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

	@GetMapping(path = "/saml/logout", produces = { MediaType.TEXT_PLAIN_VALUE })
	public ResponseEntity<String> logout() {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@PostMapping(path = "/saml", produces = { MediaType.TEXT_PLAIN_VALUE }, consumes = { MediaType.TEXT_PLAIN_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<Void> reply(HttpServletRequest request) {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		try {
			String parameter = request.getParameter("SAMLResponse");
			LOGGER.debug("Received SAMLResponse: {}", parameter);
			SamlResponse samlResp = samlClient.decodeAndValidateSamlResponse(parameter, request.getMethod());
			Assertion assertion = samlResp.getAssertion();
			assertion.getAttributeStatements().forEach(a -> {
				List<Attribute> attributes = a.getAttributes();
				attributes.forEach(attr -> {
					String name = attr.getName();
					Set<String> attrValues = attr.getAttributeValues().stream()
							.map(v -> (v instanceof XSString) ? ((XSString) v).getValue() : null)
							.collect(Collectors.toSet());
					LOGGER.debug("Attribute {} with values {}", name, StringUtils.join(attrValues, ", "));
				});
			});

			HttpHeaders headers = new HttpHeaders();
			return new ResponseEntity<>(headers, HttpStatus.FOUND);
		} catch (SamlException e) {
			LOGGER.error("Error processing SAML Response", e);
		}
		return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
	}

	@GetMapping(path = "/saml", produces = { MediaType.TEXT_PLAIN_VALUE })
	public ResponseEntity<String> reply() {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		return new ResponseEntity<>(HttpStatus.OK);
	}

}