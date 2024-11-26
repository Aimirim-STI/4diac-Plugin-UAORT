/*******************************************************************************
 * Copyright (c) 2024 AIMIRIM STI - https://en.aimirimsti.com.br/
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0/.
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *   Pedro Ricardo
 *   Felipe Adriano
 *******************************************************************************/

package com.asti.fordiac.ide.deployment.uao.helpers;
import java.util.List;
import com.google.gson.JsonObject;

public class WatchResponse {
	private final List<String> watches;
	private final JsonObject response;

	public WatchResponse(List<String> watches, JsonObject response) {
		this.watches = watches;
		this.response = response;
	}

	public List<String> getWatches() {
		return watches;
	}

	public JsonObject getResponse() {
		return response;
	}
}