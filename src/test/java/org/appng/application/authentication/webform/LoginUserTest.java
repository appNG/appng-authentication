/*
 * Copyright 2011-2023 the original author or authors.
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
package org.appng.application.authentication.webform;

import org.appng.api.FieldProcessor;
import org.appng.api.ProcessingException;
import org.appng.api.model.Subject;
import org.appng.api.support.CallableAction;
import org.appng.api.support.environment.DefaultEnvironment;
import org.appng.application.authentication.BaseLoginTest;
import org.appng.testsupport.validation.WritingXmlValidator;
import org.appng.xml.platform.Message;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.net.HttpHeaders;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LoginUserTest extends BaseLoginTest {

	static {
		WritingXmlValidator.writeXml = false;
	}

	@Test
	@Transactional
	public void testLoginOK() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);

		LoginData loginData = new LoginData();
		loginData.setUsername("subject-3");
		loginData.setPassword("test");
		CallableAction callableAction = getAction(loginData);

		Assert.assertNull(environment.getSubject());

		callableAction.perform();

		validate(callableAction.getAction());

		Subject loginSubject = environment.getSubject();
		Assert.assertNotNull(loginSubject);
		Assert.assertEquals("subject-3", loginSubject.getName());
		Assert.assertEquals("subject_username-3", loginSubject.getRealname());

		Mockito.verify(site).sendRedirect(Mockito.eq(environment), Mockito.eq("/manager/appng/appng-manager"),
				Mockito.eq(HttpStatus.FOUND.value()));
		DefaultEnvironment defaultEnv = (DefaultEnvironment) environment;
		defaultEnv.logoutSubject();
		Assert.assertEquals("frame-ancestors 'none'",
				defaultEnv.getServletResponse().getHeader(HttpHeaders.CONTENT_SECURITY_POLICY));
	}

	@Test
	@Transactional
	public void testLoginWrongPassword() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);

		LoginData loginData = new LoginData();
		loginData.setUsername("subject-3");
		loginData.setPassword("foobar");
		CallableAction callableAction = getAction(loginData);

		Assert.assertNull(environment.getSubject());
		FieldProcessor fp = callableAction.perform();
		validate(callableAction.getAction());
		Message message = fp.getMessages().getMessageList().get(0);
		Assert.assertEquals("Wrong username or password", message.getContent());
		Assert.assertNull(environment.getSubject());
	}

	@Test
	@Transactional
	public void testLoginNoData() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);

		LoginData loginData = new LoginData();
		CallableAction callableAction = getAction(loginData);

		Assert.assertNull(environment.getSubject());		
		callableAction.perform();
		validate(callableAction.getAction());
	}

	private CallableAction getAction(LoginData loginData) throws ProcessingException {
		return getAction("form-auth", "login").withParam("form_action", "loginUser").getCallableAction(loginData);
	}

}
