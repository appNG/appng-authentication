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
package org.appng.application.authentication.webform;

import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.DataContainer;
import org.appng.api.DataProvider;
import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Request;
import org.appng.api.Scope;
import org.appng.api.SiteProperties;
import org.appng.api.model.Application;
import org.appng.api.model.Properties;
import org.appng.api.model.Site;
import org.appng.api.model.Subject;
import org.appng.api.support.SelectionFactory;
import org.appng.api.support.environment.DefaultEnvironment;
import org.appng.application.authentication.AbstractLogon;
import org.appng.core.domain.SubjectImpl;
import org.appng.xml.platform.Selection;
import org.appng.xml.platform.SelectionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class LoginForm implements DataProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(LoginForm.class);
	private static final String PARAM_LANG = "lang";
	private static final String PARAM_ACTION = "action";
	private static final String SLASH = "/";

	@Autowired
	SelectionFactory selectionFactory;

	public DataContainer getData(Site site, Application application, Environment environment, Options options,
			Request request, FieldProcessor fieldProcessor) {
		DataContainer dataContainer = new DataContainer(fieldProcessor);
		Selection langSelection = processLanguage(site, environment, request);
		if (null != langSelection) {
			dataContainer.getSelections().add(langSelection);
		}
		dataContainer.setItem(new LoginData());
		return dataContainer;
	}

	private Selection processLanguage(Site site, Environment environment, Request request) {
		HttpServletRequest httpServletRequest = ((DefaultEnvironment) environment).getServletRequest();
		Properties properties = site.getProperties();
		if (null == environment.getAttribute(Scope.SESSION, AbstractLogon.PRE_LOGIN_PATH)) {
			String logoutRef = properties.getString(SiteProperties.AUTH_LOGOUT_REF);
			String authApplication = properties.getString(SiteProperties.AUTH_APPLICATION);
			String managerPath = properties.getString(SiteProperties.MANAGER_PATH);
			String queryString = httpServletRequest.getQueryString();
			String siteRootPath = managerPath + SLASH + site.getName();
			String requestedUrl = httpServletRequest.getServletPath() + (null == queryString ? "" : "?" + queryString);
			boolean isRoot = requestedUrl.equals(siteRootPath);
			boolean isManager = requestedUrl.equals(managerPath);
			boolean isLogout = requestedUrl.equals(managerPath + SLASH + logoutRef);
			boolean isAuthentication = requestedUrl.startsWith(siteRootPath + SLASH + authApplication);
			boolean hasAction = requestedUrl.startsWith(siteRootPath + SLASH + "?" + PARAM_ACTION + "=");
			if (!(isManager || isRoot || isLogout || hasAction || isAuthentication)) {
				environment.setAttribute(Scope.SESSION, AbstractLogon.PRE_LOGIN_PATH, requestedUrl);
			}
		}

		List<String> languages = properties.getList(SiteProperties.SUPPORTED_LANGUAGES, ",");
		debug("site {} supported languages: {}", site.getName(), StringUtils.join(languages, ","));
		debug("language from request: {}", request.getParameter(PARAM_LANG));
		String language = null;
		if (languages.size() >= 1) {
			language = request.getParameter(PARAM_LANG);
			boolean mustSetLanguage = true;
			if (null == language || !languages.contains(language)) {
				Subject subject = environment.getSubject();
				if (null == subject) {
					Enumeration<Locale> locales = httpServletRequest.getLocales();
					while (locales.hasMoreElements()) {
						Locale locale = locales.nextElement();
						if (languages.contains(locale.getLanguage())) {
							language = locale.getLanguage();
							debug("no subject present, retrieved language from request.getLocales(): {}", language);
							break;
						}
					}
				} else {
					language = subject.getLanguage();
					debug("retrieved language from subject#{}: {}", subject.hashCode(), language);
					mustSetLanguage = false;
				}
			}
			if (null == language) {
				language = languages.get(0);
				debug("no language set, using {}", language);
			}
			if (mustSetLanguage) {
				SubjectImpl subject = new SubjectImpl();
				subject.setLanguage(language);
				debug("created new subject#{} with language {}", subject.hashCode(), language);
				((DefaultEnvironment) environment).setSubject(subject);
				String path = httpServletRequest.getServletPath();
				String action = request.getParameter(PARAM_ACTION);
				if (null != action) {
					String completePath = path + "?" + PARAM_ACTION + "=" + action;
					debug("user must set language, redirecting to {}", completePath);
					site.sendRedirect(environment, completePath);
				}
			} else {
				language = environment.getLocale().getLanguage();
				debug("using language from environment: {}", language);
			}
		}

		String[] values = languages.toArray(new String[languages.size()]);
		Selection selection = selectionFactory.fromObjects(PARAM_LANG, "lang", values, language);
		selection.setType(SelectionType.SELECT);
		return selection;
	}

	void debug(String message, Object... args) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(message, args);
		}
	}

}
