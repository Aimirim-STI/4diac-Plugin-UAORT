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
package com.asti.fordiac.ide.deployment.uao;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Security;
import java.text.MessageFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.xmi.XMLResource;
import org.eclipse.emf.ecore.xmi.impl.XMLResourceImpl;
import org.eclipse.fordiac.ide.deployment.Activator;
import org.eclipse.fordiac.ide.deployment.data.ConnectionDeploymentData;
import org.eclipse.fordiac.ide.deployment.data.FBDeploymentData;
import org.eclipse.fordiac.ide.deployment.devResponse.DevResponseFactory;
import org.eclipse.fordiac.ide.deployment.devResponse.Response;
import org.eclipse.fordiac.ide.deployment.exceptions.DeploymentException;
import org.eclipse.fordiac.ide.deployment.iec61499.ResponseMapping;
import org.eclipse.fordiac.ide.deployment.interactors.IDeviceManagementInteractor;
import org.eclipse.fordiac.ide.deployment.monitoringbase.MonitoringBaseElement;
import org.eclipse.fordiac.ide.deployment.util.DeploymentHelper;
import org.eclipse.fordiac.ide.deployment.util.IDeploymentListener;
import org.eclipse.fordiac.ide.model.libraryElement.Device;
import org.eclipse.fordiac.ide.model.libraryElement.FB;
import org.eclipse.fordiac.ide.model.libraryElement.FBNetworkElement;
import org.eclipse.fordiac.ide.model.libraryElement.IInterfaceElement;
import org.eclipse.fordiac.ide.model.libraryElement.Resource;
import org.eclipse.fordiac.ide.model.libraryElement.VarDeclaration;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.asti.fordiac.ide.deployment.uao.helpers.Constants;
import com.asti.fordiac.ide.deployment.uao.helpers.UAOClient;
import com.asti.fordiac.ide.deployment.uao.helpers.WatchItem;
import com.asti.fordiac.ide.deployment.uao.helpers.WatchResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.neovisionaries.ws.client.WebSocket;
import com.neovisionaries.ws.client.WebSocketAdapter;
import com.neovisionaries.ws.client.WebSocketException;
import com.neovisionaries.ws.client.WebSocketFrame;

public class UAODeploymentExecutor implements IDeviceManagementInteractor {

	public enum ConnectionStatus {
		CONNECTED, DISCONNECTED, NOT_CONNECTED
	}

	private final Document deployXml;
	private Element systemElement;
	private Element deviceElement;
	private Element resourceElement;
	private Element fbNetwork;
	private Element eventConnection;
	private Element dataConnection;
	private String snapshotGuid;
	private String projectGuid;
	private int watchid = 0;
	private long fetchCount = 0;
	private long fetchErrorCount = 0;
	private final int MAX_AUTH_RETRY = 10;
	private final int MAX_FETCH_RETRY = 10;

	private ConnectionStatus connectionStatus;
	private final Device device;
	private final UAOClient client;
	private final List<IDeploymentListener> listeners = new ArrayList<>();
	private final ResponseMapping respMapping = new ResponseMapping();
	private final Map<String, List<WatchItem>> watch_items = new HashMap<>();

	/** Connection Status callback definitions */
	private final WebSocketAdapter callbacks = new WebSocketAdapter() {
		@Override
		public void onConnected(final WebSocket websocket, final Map<String, List<String>> headers) {
			connectionStatus = ConnectionStatus.CONNECTED;
			Activator.getDefault().logWarning("UAOClient Connected!"); //$NON-NLS-1$
		}

		@Override
		public void onDisconnected(final WebSocket websocket, final WebSocketFrame serverCloseFrame,
				final WebSocketFrame clientCloseFrame, final boolean closedByServer) throws DeploymentException {
			connectionStatus = ConnectionStatus.DISCONNECTED;
			Activator.getDefault().logWarning("UAOClient Disconnected!"); //$NON-NLS-1$
		}
	};

	/**
	 * Initialize UAODeploymentExecutor class.
	 *
	 * @param dev The current device.
	 */
	public UAODeploymentExecutor(final Device dev) {
		Security.addProvider(new BouncyCastleProvider());
		this.device = dev;
		this.client = createClient(dev);
		this.connectionStatus = ConnectionStatus.NOT_CONNECTED;
		this.deployXml = createInitialXml(dev);
	}

	/**
	 * Returns the initialized device.
	 *
	 * @return The current device.
	 */
	protected Device getDevice() {
		return device;
	}

	@Override
	public boolean isConnected() {
		final boolean check = connectionStatus == ConnectionStatus.CONNECTED;
		return check;
	}

	@Override
	public void connect() throws DeploymentException {
		boolean success = false;
		int retry = 0;
		String error = ""; //$NON-NLS-1$

		try {
			client.connect();
			if (client.connectionCheck()) {
				// XXX: Sometimes the credentials get denied by the runtime
				// for some unknown reason. To avoid a new click on deploy,
				// some retries are performed reseting the client key pair.
				while (retry < MAX_AUTH_RETRY) {
					try {
						success = client.authenticate();
						if (success) {
							client.registerAsWatcher();
							break;
						}
					} catch (final DeploymentException e) {
						// It usually works on the first three retries
						error = e.getMessage();
					}
					client.regenKeyPair();
					Activator.getDefault().logInfo("UAODeploymentExecutor | Auth retry " + (retry + 1)); //$NON-NLS-1$
					retry++;
				}

				if (retry >= MAX_AUTH_RETRY) {
					throw new DeploymentException("Max Authentication Retries exceeded. " + error); //$NON-NLS-1$
				}
			}
		} catch (final WebSocketException e) {
			throw new DeploymentException(e.getMessage());
		}
	}

	@Override
	public void disconnect() throws DeploymentException {
		if (client.isOpen()) {
			client.disconnect();
		}
		connectionStatus = ConnectionStatus.NOT_CONNECTED;
	}

	@Override
	public void addDeploymentListener(final IDeploymentListener listener) {
		if (!listeners.contains(listener)) {
			listeners.add(listener);
		}
	}

	@Override
	public void removeDeploymentListener(final IDeploymentListener listener) {
		if (listeners.contains(listener)) {
			listeners.remove(listener);
		}
	}

	@Override
	public void createResource(final Resource resource) throws DeploymentException {
		resourceElement = deployXml.createElement("Resource"); //$NON-NLS-1$
		resourceElement.setAttribute("Name", resource.getName()); //$NON-NLS-1$
		resourceElement.setAttribute("Type", resource.getTypeName()); //$NON-NLS-1$

		fbNetwork = deployXml.createElement("FBNetwork"); //$NON-NLS-1$
		eventConnection = deployXml.createElement("EventConnections"); //$NON-NLS-1$
		dataConnection = deployXml.createElement("DataConnections"); //$NON-NLS-1$

		resourceElement.appendChild(fbNetwork);
		deviceElement.appendChild(resourceElement);
	}

	@Override
	public void writeResourceParameter(final Resource resource, final String parameter, final String value) {
		// Activator.getDefault().logInfo("UAODeploymentExecutor |
		// writeResourceParameter "+parameter+"="+value); //$NON-NLS-1$
	}

	@Override
	public void writeDeviceParameter(final Device device, final String parameter, final String value) {
		// Activator.getDefault().logInfo("UAODeploymentExecutor | writeDeviceParameter
		// "+parameter+"="+value); //$NON-NLS-1$
	}

	@Override
	public void createFBInstance(final FBDeploymentData fbData, final Resource res) throws DeploymentException {
		// client.connectionCheck();
		final FBNetworkElement fb = fbData.getFb();
		Document fbt = null;
		try {
			fbt = xmlRead(fb.getPaletteEntry().getFile().getContents());
		} catch (final CoreException e) {
			e.printStackTrace();
		}
		String ns = "IEC61499.Standard"; //$NON-NLS-1$
		if (fbt != null) {
			final String nsfile = fbt.getDocumentElement().getAttribute("Namespace"); //$NON-NLS-1$
			if ((nsfile != null) && !nsfile.isEmpty()) {
				ns = nsfile;
			}
		}
		if (fbNetwork != null) {
			fbNetwork.appendChild(createFB(prefixUAO(fbData.getPrefix()) + fb.getName(), fb.getTypeName(), ns));
		}
	}

	@Override
	public void writeFBParameter(final Resource resource, final String value, final FBDeploymentData fbData,
			final VarDeclaration varDecl) throws DeploymentException {
		// client.connectionCheck();
		final FBNetworkElement fb = fbData.getFb();

		final String fbFullName = prefixUAO(fbData.getPrefix()) + fb.getName();
		final Element fbFound = findFbByName(fbFullName);
		if (fbFound != null) {
			fbFound.appendChild(createParameter(varDecl.getName(), value));
		}
	}

	@Override
	public void createConnection(final Resource res, final ConnectionDeploymentData connData)
			throws DeploymentException {
		// client.connectionCheck();
		final IInterfaceElement sourceData = connData.getSource();
		final IInterfaceElement destinationData = connData.getDestination();

		if (sourceData == null || sourceData.getFBNetworkElement() == null || destinationData == null
				|| destinationData.getFBNetworkElement() == null) {
			throw new DeploymentException(MessageFormat
					.format(Messages.UAODeploymentExecutor_CreateConnectionFailedNoDataFound, res.getName()));
		}

		final FBNetworkElement sourceFB = sourceData.getFBNetworkElement();
		final FBNetworkElement destinationFB = destinationData.getFBNetworkElement();
		final String source = String.format("%s%s.%s", prefixUAO(connData.getSourcePrefix()), sourceFB.getName(), //$NON-NLS-1$
				sourceData.getName());
		final String destination = String.format("%s%s.%s", prefixUAO(connData.getDestinationPrefix()), //$NON-NLS-1$
				destinationFB.getName(), destinationData.getName());

		if (sourceData.getTypeName() == "Event" && destinationData.getTypeName() == "Event") { //$NON-NLS-1$ //$NON-NLS-2$
			eventConnection.appendChild(createConnection(source, destination));
		} else {
			dataConnection.appendChild(createConnection(source, destination));
		}
	}

	@Override
	public void startFB(final Resource res, final FBDeploymentData fbData) throws DeploymentException {
//		Activator.getDefault().logInfo("UAODeploymentExecutor | startFB"); //$NON-NLS-1$
	}

	@Override
	public void startResource(final Resource resource) throws DeploymentException {
		// client.connectionCheck();
		final String from = client.getDeviceState();
		if (fbNetwork != null) {
			// XXX: UAO Runtime does not have an implicit START block. It needs to be
			// deployed.
			// To fix this a new resource that does not already have a START FB is needed.
			final FB fb = resource.getFBNetwork().getFBNamed("START"); //$NON-NLS-1$
			if (fb != null) {
				fbNetwork.appendChild(createFB(fb.getName(), fb.getTypeName()));
			}
			// Append the connections after all FBs were inserted in FBNetwork
			fbNetwork.appendChild(eventConnection);
			fbNetwork.appendChild(dataConnection);
			// Start deploy
			client.deploy(deployXml, projectGuid, snapshotGuid);
			final String to = client.getDeviceState();
			Activator.getDefault().logInfo("UAODeploymentExecutor | Resource \""+resource.getName()+"\" state from [" + from + "] to [" + to + "]"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$  //$NON-NLS-4$
		}
	}

	@Override
	public void startDevice(final Device dev) throws DeploymentException {
		// client.connectionCheck();
		final String from = client.getDeviceState();
		client.flow_command("start"); //$NON-NLS-1$
		final String to = client.getDeviceState();
		Activator.getDefault().logInfo("UAODeploymentExecutor | Device \""+dev.getName()+"\" state from [" + from + "] to [" + to + "]"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
	}

	@Override
	public void deleteResource(final String resName) throws DeploymentException {
		// client.connectionCheck();
		final String from = client.getDeviceState();
		client.flow_command("clean"); //$NON-NLS-1$
		final String to = client.getDeviceState();
		Activator.getDefault().logInfo("UAODeploymentExecutor | Resource \""+resName+"\" state from [" + from + "] to [" + to + "]"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
	}

	@Override
	public void deleteFB(final Resource res, final FBDeploymentData fbData) throws DeploymentException {
		throw new DeploymentException(
				MessageFormat.format(Messages.UAODeploymentExecutor_FeatureNotImplemented, "Online Change Delete FB")); //$NON-NLS-1$
	}

	@Override
	public void deleteConnection(final Resource res, final ConnectionDeploymentData connData)
			throws DeploymentException {
		throw new DeploymentException(MessageFormat.format(Messages.UAODeploymentExecutor_FeatureNotImplemented,
				"Online Change Delete Connection")); //$NON-NLS-1$

	}

	@Override
	public void killDevice(final Device dev) throws DeploymentException {
		// client.connectionCheck();
		client.reboot();
	}

	@Override
	public List<org.eclipse.fordiac.ide.deployment.devResponse.Resource> queryResources() throws DeploymentException {
		// client.connectionCheck();
		List<String> reslist = client.registerAsWatcher();
		if (reslist == null || reslist.isEmpty()) {
			return Collections.emptyList();
		}
		return reslist.stream().map(resName -> {
			final org.eclipse.fordiac.ide.deployment.devResponse.Resource res = DevResponseFactory.eINSTANCE
					.createResource();
			res.setName(resName);
			res.setType(resName);
			return res;
		}).toList();
	}

	@Override
	public Response readWatches() throws DeploymentException {
		fetchCount += 1;
		// client.connectionCheck();
		WatchResponse resp = null;
		JsonArray forceResponse = new JsonArray();
		if (!watch_items.isEmpty()) {
			for (final Resource res : device.getResource()) {
				if (!watch_items.get(res.getName()).isEmpty()) {
					try {
						resp = client.fetchWatches(res.getName());
						if (resp.getResponse().get("result").getAsInt()==400) { //$NON-NLS-1$
							Activator.getDefault().logInfo("UAODeploymentExecutor | readWatches | Runtime is busy."); //$NON-NLS-1$
						} else {
							UAOClient.parseError(resp.getResponse());
						}
						forceResponse = client.forceQuery(res.getName());
						fetchErrorCount=0; // Reset errors
					} catch (final DeploymentException e) {
						fetchErrorCount+=1;
						if (fetchErrorCount>MAX_FETCH_RETRY){
							Activator.getDefault().logError(e.getMessage());
							throw e;
						}
						Activator.getDefault().logWarning(e.getMessage()+" Retry attempt "+fetchErrorCount+" of "+MAX_FETCH_RETRY+"."); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
					}
					int wlid = 0;
					if (resp!=null) {
						for (final String value : resp.getWatches()) {
							watch_items.get(res.getName()).get(wlid).setValue(value);
							wlid += 1;
						}
					}
					for (final JsonElement forceVariable : forceResponse) {
						final JsonObject force = forceVariable.getAsJsonObject();
						final String forcePath = force.get("path").getAsString(); //$NON-NLS-1$
						for (final WatchItem item : watch_items.get(res.getName())) {
							final String portPath = prefixUAO(item.fbName) + "." + item.portName; //$NON-NLS-1$
							if (forcePath.equals(portPath)) {
								item.setForce(force.get("enable").getAsBoolean()); //$NON-NLS-1$
								item.setValue(force.get("value").getAsString()); //$NON-NLS-1$
							}
						}
					}
				}
			}
		}
		Response watches = Constants.EMPTY_RESPONSE;
		try {
			if (resp!=null) {
				watches = parseWatchResponse(watch_items, fetchCount);
			}
		} catch (final IOException | TransformerException e) {
			e.printStackTrace();
		}
		return (watches);
	}

	@Override
	public void addWatch(final MonitoringBaseElement element) throws DeploymentException {
		// client.connectionCheck();
		String portPath = element.getQualifiedString();
		final String uaoPortPath[] = portPath.split("[.](?=[^.]*$)"); //$NON-NLS-1$
		final String fbName = uaoPortPath[0];
		final String portName = uaoPortPath[1];
		final String uaoFbName = prefixUAO(fbName);
		portPath = uaoFbName + "." + portName; //$NON-NLS-1$
		final String resName = element.getResourceString();
		final String dataType = element.getPort().getInterfaceElement().getType().getName();

		final boolean check = client.addWatch(resName, portPath, watchid);
		element.setOffline(!check);
		if (check) {
			final WatchItem wele = new WatchItem(watchid, fbName, portName, dataType);
			if (!watch_items.containsKey(resName)) {
				watch_items.put(resName, new ArrayList<>());
			}
			watch_items.get(resName).add(wele);
			watchid += 1;
			Activator.getDefault().logInfo("UAODeploymentExecutor | addWatch " + portPath + " Added"); //$NON-NLS-1$ //$NON-NLS-2$
		}
	}

	@Override
	public void removeWatch(final MonitoringBaseElement element) throws DeploymentException {
		// client.connectionCheck();
		final String resName = element.getResourceString();
		String portPath = element.getQualifiedString();
		final String uaoPortPath[] = portPath.split("[.](?=[^.]*$)"); //$NON-NLS-1$
		final String fbName = prefixUAO(uaoPortPath[0]);
		final String portName = uaoPortPath[1];
		portPath = fbName + "." + portName; //$NON-NLS-1$
		int id = -1;
		for (final WatchItem item : watch_items.get(resName)) {
			if (item.portName.equals(portName)) {
				id = item.id;
				try {
					final boolean check = client.removeWatch(resName, id);
					if (check) {
						watch_items.get(resName).remove(item);
						Activator.getDefault().logInfo("UAODeploymentExecutor | removeWatch " + portPath + " Removed"); //$NON-NLS-1$ //$NON-NLS-2$
					}
				} catch (final DeploymentException e) {
					throw e;
				}
				break;
			}
		}
	}

	@Override
	public void triggerEvent(final MonitoringBaseElement element) throws DeploymentException {
		// client.connectionCheck();
		String portPath = element.getQualifiedString();
		final String uaoPortPath[] = portPath.split("[.](?=[^.]*$)"); //$NON-NLS-1$
		final String fbName = uaoPortPath[0];
		final String portName = uaoPortPath[1];
		final String uaoFbName = prefixUAO(fbName);
		portPath = uaoFbName + "." + portName; //$NON-NLS-1$
		final String resName = element.getResourceString();

		for (final WatchItem item : watch_items.get(resName)) {
			final String itemPortPath = prefixUAO(item.fbName) + "." + item.portName; //$NON-NLS-1$
			if (itemPortPath.equals(portPath)) {
				client.triggerEvent(resName, portPath);
				break;
			}
		}

	}

	@Override
	public void forceValue(final MonitoringBaseElement element, final String value) throws DeploymentException {
		// client.connectionCheck();
		String portPath = element.getQualifiedString();
		final String uaoPortPath[] = portPath.split("[.](?=[^.]*$)"); //$NON-NLS-1$
		final String fbName = uaoPortPath[0];
		final String portName = uaoPortPath[1];
		final String uaoFbName = prefixUAO(fbName);
		portPath = uaoFbName + "." + portName; //$NON-NLS-1$
		final String resName = element.getResourceString();

		for (final WatchItem item : watch_items.get(resName)) {
			final String itemPortPath = prefixUAO(item.fbName) + "." + item.portName; //$NON-NLS-1$
			if (itemPortPath.equals(portPath)) {
				final boolean check = client.forceValue(true, resName, portPath, value);
				if (check) {
					item.setForce(true);
					item.setValue(value);
				}
				break;
			}
		}
	}

	@Override
	public void clearForce(final MonitoringBaseElement element) throws DeploymentException {
		// client.connectionCheck();
		String portPath = element.getQualifiedString();
		final String uaoPortPath[] = portPath.split("[.](?=[^.]*$)"); //$NON-NLS-1$
		final String fbName = uaoPortPath[0];
		final String portName = uaoPortPath[1];
		final String uaoFbName = prefixUAO(fbName);
		portPath = uaoFbName + "." + portName; //$NON-NLS-1$
		final String resName = element.getResourceString();

		for (final WatchItem item : watch_items.get(resName)) {
			final String itemPortPath = prefixUAO(item.fbName) + "." + item.portName; //$NON-NLS-1$
			if (itemPortPath.equals(portPath)) {
				final boolean check = client.forceValue(false, resName, portPath, null);
				if (check) {
					item.setForce(false);
				}
				break;
			}
		}
	}

	/**
	 * Parse the 4diac '.' prefix to the UAO '_' one
	 *
	 * @param original 4diac FB prefix.
	 * @return UAO type of prefix.
	 */
	private static String prefixUAO(final String original) {
		String uaoFormat = original;
		if (original.contains(".")) { //$NON-NLS-1$
			uaoFormat = original.replace(".", "_"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		return (uaoFormat);
	}

	/**
	 * Extract SSL information from device variables.
	 *
	 * @param dev The current device.
	 * @return useSSL configured value.
	 */
	private static boolean getUseSsl(final Device dev) throws DeploymentException {
		for (final VarDeclaration varDecl : dev.getVarDeclarations()) {
			if ("SSL".equalsIgnoreCase(varDecl.getName())) { //$NON-NLS-1$
				final String val = DeploymentHelper.getVariableValue(varDecl, dev.getAutomationSystem());
				if (null != val) {
					return (Boolean.parseBoolean(val));
				}
			}
		}
		return false;
	}

	/**
	 * Creates and configure the UAO connection.
	 *
	 * @param dev The current device.
	 */
	private UAOClient createClient(final Device dev) {
		String mgrId = ""; //$NON-NLS-1$
		mgrId = DeploymentHelper.getMgrID(dev);
		if (mgrId.equals("")) {
			Activator.getDefault().logError(
					MessageFormat.format(Messages.UAODeploymentExecutor_GetMgrIDFailed, "Empty MGR_ID value."));
		}
		// Remove Quotes from string
		mgrId = mgrId.substring(1, mgrId.length() - 1);

		boolean ssl = false;
		try {
			ssl = getUseSsl(dev);
		} catch (final DeploymentException e) {
			Activator.getDefault().logError(MessageFormat.format(Messages.UAODeploymentExecutor_GetSSLFailed, e.getMessage()), e);
		}

		UAOClient newClient = null;
		try {
			newClient = new UAOClient(mgrId, 0, ssl);
			newClient.addListener(callbacks);
		} catch (final DeploymentException e) {
			Activator.getDefault().logError(
					MessageFormat.format(Messages.UAODeploymentExecutor_ClientConnectionFailed, e.getMessage()), e);
		}

		return newClient;
	}

	/**
	 * Creates an empty XML Document type
	 *
	 * @return An XML document
	 */
	private static Document createXmlDocument() {
		final DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = null;
		try {
			docBuilder = docFactory.newDocumentBuilder();
		} catch (final ParserConfigurationException e) {
			e.printStackTrace();
		}
		Document doc = null;
		if (docBuilder != null) {
			doc = docBuilder.newDocument();
		}
		return (doc);
	}

	/**
	 * Build the xml document to keep the deploy data.
	 *
	 * @param dev Device to deploy.
	 * @return A initial XML with the system and device already in it.
	 */
	private Document createInitialXml(final Device dev) {
		final Document doc = createXmlDocument();
		if (doc != null) {
			systemElement = createSystem(doc, dev);
			deviceElement = createDevice(doc, dev);
			systemElement.appendChild(deviceElement);
			doc.appendChild(systemElement);
		}
		return (doc);
	}

	/**
	 * Creates the System xml element.
	 *
	 * @param doc XML document.
	 * @param dev Device to deploy.
	 * @return XML Element.
	 */
	private Element createSystem(final Document doc, final Device dev) {
		final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss"); //$NON-NLS-1$
		final LocalDateTime now = LocalDateTime.now();
		final String version = System.getProperty("org.eclipse.fordiac.ide.version"); //$NON-NLS-1$

		final String projName = "4diac Project"; //$NON-NLS-1$

		final Element sysEl = doc.createElement("System"); //$NON-NLS-1$

		this.projectGuid = UUID.nameUUIDFromBytes(projName.getBytes()).toString();
		this.snapshotGuid = UUID.randomUUID().toString();

		sysEl.setAttribute("ProjectName", projName); // 4diac Project Name //$NON-NLS-1$
		sysEl.setAttribute("ProjectGuid", projectGuid); //$NON-NLS-1$
		sysEl.setAttribute("BuildTime", dtf.format(now)); //$NON-NLS-1$
		sysEl.setAttribute("DeployTime", ""); //$NON-NLS-1$ //$NON-NLS-2$
		sysEl.setAttribute("StudioVersion", "Eclipse 4diac IDE v" + version); // 4diac //$NON-NLS-1$ //$NON-NLS-2$
																				// version info
		sysEl.setAttribute("SnapshotGuid", snapshotGuid); //$NON-NLS-1$

		return (sysEl);
	}

	/**
	 * Creates a Device xml element.
	 *
	 * @param doc XML document.
	 * @param dev Device to deploy.
	 * @return XML Element.
	 */
	private static Element createDevice(final Document doc, final Device dev) {
		final Element devEl = doc.createElement("Device"); //$NON-NLS-1$
		devEl.setAttribute("Name", dev.getName()); //$NON-NLS-1$
		devEl.setAttribute("Type", dev.getTypeName()); //$NON-NLS-1$
		return (devEl);
	}

	/**
	 * Search for a FB by it's name in class FBNetwork.
	 *
	 * @param fbFullName The name with all prefixes.
	 * @return XML Element.
	 */
	private Element findFbByName(final String fbFullName) {
		Element fb = null;
		if (fbNetwork != null) {
			final NodeList fblist = fbNetwork.getElementsByTagName("FB"); //$NON-NLS-1$
			for (int i = 0; i < fblist.getLength(); i++) {
				final Element fbi = (Element) fblist.item(i);
				if (fbi.getAttribute("Name").equals(fbFullName)) { //$NON-NLS-1$
					fb = fbi;
					break;
				}
			}
		}
		return (fb);
	}

	/**
	 * Creates a Parameter xml element
	 *
	 * @param Name
	 * @param Value
	 * @return
	 */
	private Element createParameter(final String Name, final String Value) {
		final Element param = deployXml.createElement("Parameter"); //$NON-NLS-1$
		param.setAttribute("Name", Name); //$NON-NLS-1$
		// Remove possible surrounding quotes on string
		String stringValue = Value.replaceAll("^\"|\"$", ""); //$NON-NLS-1$//$NON-NLS-2$
		stringValue = stringValue.replaceAll("^'|'$", ""); //$NON-NLS-1$//$NON-NLS-2$
		param.setAttribute("Value", stringValue); //$NON-NLS-1$
		return (param);
	}

	/**
	 * Creates a FB xml element assuming the namespace to "IEC61499.Standard".
	 *
	 * @param Name with all prefixes needed.
	 * @param Type
	 * @return FB element.
	 */
	private Element createFB(final String Name, final String Type) {
		return (createFB(Name, Type, "IEC61499.Standard")); //$NON-NLS-1$
	}

	/**
	 * Creates a FB xml element.
	 *
	 * @param Name      with all prefixes needed.
	 * @param Type
	 * @param Namespace where the runtime will find the implementation
	 * @return FB element.
	 */
	private Element createFB(final String Name, final String Type, final String Namespace) {
		final Element fbEl = deployXml.createElement("FB"); //$NON-NLS-1$
		fbEl.setAttribute("Name", Name); //$NON-NLS-1$
		fbEl.setAttribute("Type", Type); //$NON-NLS-1$
		fbEl.setAttribute("Namespace", Namespace); //$NON-NLS-1$
		return (fbEl);
	}

	/**
	 * Creates a connection xml element.
	 *
	 * @param Src  Name of the connection source.
	 * @param Dest Name of the connection destination.
	 * @return XML element.
	 */
	private Element createConnection(final String Src, final String Dest) {
		final Element conEl = deployXml.createElement("Connection"); //$NON-NLS-1$
		conEl.setAttribute("Comment", ""); //$NON-NLS-1$ //$NON-NLS-2$
		conEl.setAttribute("Source", Src); //$NON-NLS-1$
		conEl.setAttribute("Destination", Dest); //$NON-NLS-1$
		return (conEl);
	}

	/**
	 * Description
	 *
	 * @param result
	 * @return
	 * @throws IOException
	 * @throws TransformerException
	 */
	private Response parseWatchResponse(final Map<String, List<WatchItem>> watches, final long id)
			throws IOException, TransformerException {
		if (watches.isEmpty()) {
			return Constants.EMPTY_RESPONSE;
		}
		final Document doc = createXmlDocument();
		final Element respEl = doc.createElement("Response"); //$NON-NLS-1$
		respEl.setAttribute("ID", String.valueOf(id)); //$NON-NLS-1$
		doc.appendChild(respEl);
		final Element watchEl = doc.createElement("Watches"); //$NON-NLS-1$
		respEl.appendChild(watchEl);
		Element resEl = null;
		Element fbEl = null;
		Element portEl = null;
		final Map<String, List<WatchItem>> fbWatchMap = new HashMap<>();

		for (final String res : watches.keySet()) {
			resEl = doc.createElement("Resource"); //$NON-NLS-1$
			resEl.setAttribute("name", res); //$NON-NLS-1$
			fbWatchMap.clear();
			for (final WatchItem item : watches.get(res)) {
				if (!fbWatchMap.containsKey(item.fbName)) {
					fbWatchMap.put(item.fbName, new ArrayList<>());
				}
				fbWatchMap.get(item.fbName).add(item);
			}
			for (final String fb : fbWatchMap.keySet()) {
				fbEl = doc.createElement("FB"); //$NON-NLS-1$
				fbEl.setAttribute("name", fb); //$NON-NLS-1$
				resEl.appendChild(fbEl);
				for (final WatchItem item : fbWatchMap.get(fb)) {
					portEl = item.getPortElement(doc);
					fbEl.appendChild(portEl);
				}
			}
			if (resEl.hasChildNodes()) {
				watchEl.appendChild(resEl);
			}
		}
		if (!watchEl.hasChildNodes()) {
			return (Constants.EMPTY_RESPONSE);
		}
		final String xml = xmlToString(doc);
//		Activator.getDefault().logInfo("Pooling: " + xml); //$NON-NLS-1$
		return parseXMLResponse(xml);
	}

	/**
	 * Reads a XML string into the 4diac xml object
	 *
	 * @param strResponse A xml written as string
	 * @return 4diac Response xml object
	 * @throws IOException
	 */
	private Response parseXMLResponse(final String strResponse) throws IOException {
		if (null != strResponse) {
			final InputSource source = new InputSource(new StringReader(strResponse));
			final XMLResource xmlResource = new XMLResourceImpl();
			xmlResource.load(source, respMapping.getLoadOptions());
			for (final EObject object : xmlResource.getContents()) {
				if (object instanceof final Response response) {
					return response;
				}
			}
		}
		return Constants.EMPTY_RESPONSE;
	}

	/**
	 * Transform a xml Document into a string.
	 *
	 * @param doc The xml document object.
	 * @return A string representation of the XML.
	 * @throws TransformerException
	 */
	private static String xmlToString(final Document doc) throws TransformerException {
		final TransformerFactory tf = TransformerFactory.newInstance();
		final Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "no"); //$NON-NLS-1$
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes"); //$NON-NLS-1$
		final StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		return (writer.toString());
	}

	/**
	 * Read a xml file into a Document.
	 *
	 * @param stream The file object.
	 * @return readed document or null if fail.
	 */
	private static Document xmlRead(final InputStream stream) {
		final DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = null;
		Document doc = null;
		try {
			docFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false); //$NON-NLS-1$
			docBuilder = docFactory.newDocumentBuilder();
		} catch (final ParserConfigurationException e) {
			e.printStackTrace();
		}
		try {
			if (docBuilder != null) {
				doc = docBuilder.parse(stream);
			}
		} catch (SAXException | IOException e) {
			e.printStackTrace();
		}
		return (doc);
	}

}
