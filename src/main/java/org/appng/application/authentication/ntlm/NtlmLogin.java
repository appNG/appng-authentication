/*
 * Copyright 2011-2020 the original author or authors.
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
package org.appng.application.authentication.ntlm;

import java.security.Principal;

import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Request;
import org.appng.api.model.Application;
import org.appng.api.model.Site;
import org.appng.api.support.environment.DefaultEnvironment;
import org.appng.application.authentication.AbstractLogon;
import org.appng.application.authentication.webform.LoginData;
import org.appng.core.service.CoreService;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

/**
 * Performs a login using the current {@link Principal}.
 * 
 * @author Matthias Herlitzius
 * @see    CoreService#login(Environment, Principal)
 */
@Slf4j
@Service
public class NtlmLogin extends AbstractLogon {

	protected NtlmLogin(CoreService coreService) {
		super(coreService);
	}

	public void perform(Site site, Application application, Environment environment, Options options, Request request,
			LoginData loginData, FieldProcessor fp) {
		if (!environment.isSubjectAuthenticated()) {
			Principal principal = ((DefaultEnvironment) environment).getServletRequest().getUserPrincipal();
			boolean success = coreService.login(environment, principal);
			processLogonResult(site, application, environment, options, fp, success);
		}
	}

	protected Logger log() {
		return LOGGER;
	}

}
