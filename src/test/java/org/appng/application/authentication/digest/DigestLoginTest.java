/*
 * Copyright 2011-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.appng.application.authentication.digest;

import java.util.List;

import org.appng.api.Platform;
import org.appng.api.Scope;
import org.appng.api.Session;
import org.appng.api.model.Property;
import org.appng.api.model.SimpleProperty;
import org.appng.api.support.environment.DefaultEnvironment;
import org.appng.application.authentication.BaseLoginTest;
import org.appng.application.authentication.webform.AuthenticationTestDataProvider;
import org.appng.core.security.DigestUtil;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;

public class DigestLoginTest extends BaseLoginTest {

	private static final String SHARED_SECRET = "secret";

	@Override
	protected List<Property> getPlatformProperties(String prefix) {
		List<Property> platformProperties = super.getPlatformProperties(prefix);
		platformProperties.add(new SimpleProperty(prefix + Platform.Property.SHARED_SECRET, SHARED_SECRET));
		return platformProperties;
	}

	@Test
	@Transactional
	public void testLoginOk() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);
		addParameter("digest", DigestUtil.getDigest("subject-3", SHARED_SECRET));
		initParameters();
		Assert.assertNull(environment.getSubject());
		doTest();
		Assert.assertNotNull(environment.getSubject());
		Mockito.verify(site).sendRedirect(Mockito.eq(environment), Mockito.eq("/manager/appng/appng-manager"),
				Mockito.eq(HttpStatus.FOUND.value()));
	}

	@Test
	@Transactional
	public void testLoginForwardOk() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);
		addParameter("digest", DigestUtil.getDigest("subject-3", SHARED_SECRET));
		String forward = "/manager/appng/appng-manager/system";
		addParameter("forward", forward);
		initParameters();
		Assert.assertNull(environment.getSubject());
		doTest();
		Assert.assertNotNull(environment.getSubject());
		Mockito.verify(site).sendRedirect(Mockito.eq(environment), Mockito.eq("/manager/appng/appng/appng-manager/system"),
				Mockito.eq(HttpStatus.FOUND.value()));
		
		environment.removeAttribute(Scope.SESSION, Session.Environment.SUBJECT);
	}

	@Test
	@Transactional
	public void testLoginError() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);
		((DefaultEnvironment) environment).logoutSubject();
		addParameter("digest", DigestUtil.getDigest("subject-3", "asasd"));
		initParameters();
		Assert.assertNull(environment.getSubject());
		doTest();
		Assert.assertNull(environment.getSubject());
	}

	private void doTest() throws Exception {
		getAction("digest-login", "login").getCallableAction(null).perform();
	}

}
