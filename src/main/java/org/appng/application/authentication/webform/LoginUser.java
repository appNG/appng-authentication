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

import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Request;
import org.appng.api.model.Application;
import org.appng.api.model.Site;
import org.appng.application.authentication.AbstractLogon;
import org.appng.core.service.CoreService;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

/**
 * Performs a user login with a username and a password.
 * 
 * @author Matthias Herlitzius
 * @see    CoreService#login(Site, Environment, String, String)
 */
@Slf4j
@Service
public class LoginUser extends AbstractLogon {

	public LoginUser(CoreService coreService) {
		super(coreService);
	}

	public void perform(Site site, Application application, Environment environment, Options options, Request container,
			LoginData loginData, FieldProcessor fp) {
		if (!environment.isSubjectAuthenticated()) {
			String username = loginData.getUsername();
			String password = loginData.getPassword();
			boolean success = coreService.login(site, environment, username, password);
			processLogonResult(site, application, environment, options, fp, success);
		}
	}

	protected Logger log() {
		return LOGGER;
	}

}
