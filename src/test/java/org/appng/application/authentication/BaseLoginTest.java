/*
 * Copyright 2011-2017 the original author or authors.
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

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.appng.api.Scope;
import org.appng.api.support.environment.EnvironmentKeys;
import org.appng.testsupport.TestBase;
import org.junit.Before;
import org.junit.Ignore;
import org.springframework.test.context.ContextConfiguration;

@Ignore("can not be abstract, so ignore")
@ContextConfiguration(locations = { TestBase.TESTCONTEXT_JPA, TestBase.TESTCONTEXT_CORE }, initializers = BaseLoginTest.class)
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

}
