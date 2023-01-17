package org.appng.application.authentication.saml;

import org.appng.api.model.Site;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * <a href= "https://learn.microsoft.com/de-de/azure/active-directory/fundamentals/auth-saml"><img alt="SAML Auth" src=
 * "https://learn.microsoft.com/de-de/azure/active-directory/fundamentals/media/authentication-patterns/saml-auth.png"
 * /></a>
 */
@RestController
public class SamlController {

	private @Autowired Site site;

	@PostMapping(path = "/saml/sign-on", produces = { MediaType.TEXT_PLAIN_VALUE }, consumes = {
			MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<String> signOn(@RequestBody String payload) {
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

	@GetMapping(path = "/saml/sign-on", produces = { MediaType.TEXT_PLAIN_VALUE })
	public ResponseEntity<String> signOn() {
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@PostMapping(path = "/saml/logout", produces = { MediaType.TEXT_PLAIN_VALUE }, consumes = {
			MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<String> logout(@RequestBody String payload) {
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

	@GetMapping(path = "/saml/logout", produces = { MediaType.TEXT_PLAIN_VALUE })
	public ResponseEntity<String> logout() {
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@PostMapping(path = "/saml", produces = { MediaType.TEXT_PLAIN_VALUE }, consumes = { MediaType.TEXT_PLAIN_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<String> reply(@RequestBody String payload) {
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

	@GetMapping(path = "/saml", produces = { MediaType.TEXT_PLAIN_VALUE })
	public ResponseEntity<String> reply() {
		return new ResponseEntity<>(HttpStatus.OK);
	}

}