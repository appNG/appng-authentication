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
package org.appng.application.authentication.digest;

import java.awt.Desktop;
import java.net.URI;
import java.net.URLEncoder;

import org.appng.core.security.DigestUtil;

public class Digestgenerator {

	public static void main(String[] args) throws Exception {
		String user = "admin";
		String sharedSecret = "thisisreallysecret";
		String digest = URLEncoder.encode(DigestUtil.getDigest(user, sharedSecret), "UTF-8");
		String domain = "http://localhost:8080";
		String site = "manager";
		String forwardTo = String.format("/manager/%s/appng-manager/sites", site);
		String uri = String.format("%s/manager/%s/appng-authentication/digestlogin?digest=%s&forward=%s", domain, site,
				digest, forwardTo);
		System.err.println(uri);
		Desktop.getDesktop().browse(new URI(uri));
	}

}
