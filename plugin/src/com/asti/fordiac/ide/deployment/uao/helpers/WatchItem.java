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

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class WatchItem {
	public int id;
	public String fbName;
	public String portName;
	public String dataType;
	private String value = "N/A"; //$NON-NLS-1$
	private boolean forced = false;

	public WatchItem(final int id_num, final String fbname, final String pname, final String tname) {
		id = id_num;
		fbName = fbname;
		portName = pname;
		dataType = tname;
	}

	public void setValue(final String val) {
		value = val;
	}

	public void setForce(final boolean force) {
		forced = force;
	}

	public Element getPortElement(final Document doc) {
		final Element ele = doc.createElement("Port"); //$NON-NLS-1$
		ele.setAttribute("name", portName); //$NON-NLS-1$

		final Element data = doc.createElement("Data"); //$NON-NLS-1$
		data.setAttribute("value", value); //$NON-NLS-1$
		if (!dataType.equals("Event")) { //$NON-NLS-1$
			data.setAttribute("forced", String.valueOf(forced)); //$NON-NLS-1$
		}

		ele.appendChild(data);

		return (ele);
	}
}
