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
package org.appng.application.authentication;

import java.io.File;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.appng.api.Platform;
import org.appng.api.ProcessingException;
import org.appng.api.Scope;
import org.appng.api.model.Property;
import org.appng.api.model.SimpleProperty;
import org.appng.api.support.CallableAction;
import org.appng.api.support.environment.EnvironmentKeys;
import org.appng.application.authentication.webform.LoginData;
import org.appng.testsupport.TestBase;
import org.junit.Before;
import org.junit.Ignore;
import org.springframework.test.context.ContextConfiguration;

@Ignore("can not be abstract, so ignore")
@ContextConfiguration(locations = { TestBase.TESTCONTEXT_JPA,
		TestBase.TESTCONTEXT_CORE }, initializers = BaseLoginTest.class)
public class BaseLoginTest extends TestBase {

	@PersistenceContext
	public EntityManager em;

	public BaseLoginTest() {
		super("appng-authentication", "application-home");
		setEntityPackage("org.appng.core.domain");
		setRepositoryBase("org.appng.core.repository");
	}

	@Before
	public void setup() throws Exception {
		super.setup();
		environment.setAttribute(Scope.REQUEST, EnvironmentKeys.EXECUTE_PATH, "/manager");
		environment.setAttribute(Scope.REQUEST, EnvironmentKeys.SERVLETPATH, "/manager");
		environment.setAttribute(Scope.REQUEST, EnvironmentKeys.BASE_URL, "/manager/appng");
	}

	@Override
	protected List<Property> getPlatformProperties(String prefix) {
		List<Property> platformProperties = super.getPlatformProperties(prefix);
		platformProperties.add(new SimpleProperty(prefix + Platform.Property.MAX_LOGIN_ATTEMPTS, "3"));
		platformProperties.add(new SimpleProperty(prefix + Platform.Property.APPNG_DATA, "."));
		// JDK-8254876 first segment of Path must exist!
		new File("target/uploads").mkdirs();
		return platformProperties;
	}

	protected CallableAction getLoginAction(LoginData loginData) throws ProcessingException {
		return getAction("form-auth", "login").withParam("form_action", "loginUser").getCallableAction(loginData);
	}
}
