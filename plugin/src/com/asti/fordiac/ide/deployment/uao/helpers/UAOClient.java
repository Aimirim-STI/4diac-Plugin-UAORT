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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.BasicHttpContext;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.eclipse.fordiac.ide.deployment.exceptions.DeploymentException;
import org.eclipse.fordiac.ide.deployment.Activator;
import org.w3c.dom.Document;

import com.asti.fordiac.ide.deployment.uao.Messages;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.neovisionaries.ws.client.WebSocket;
import com.neovisionaries.ws.client.WebSocketAdapter;
import com.neovisionaries.ws.client.WebSocketException;
import com.neovisionaries.ws.client.WebSocketFactory;
import com.neovisionaries.ws.client.WebSocketListener;

public class UAOClient {

	private final WebSocket ws;
	private final String endpoint;
	private final SecureRandom rand = new SecureRandom();
	private ECPrivateKeyParameters privKey;
	private ECPublicKeyParameters pubKey;
	private ECNamedCurveParameterSpec curveSpec;
	private ECDomainParameters curveParams;
	private byte[] sharedSecret;
	private byte[] ticket;
	private int session_id;
	private int reqid = 1;
	private int msgnr = 0;
	private String current_role = ""; //$NON-NLS-1$
	private byte[] current_role_iv = null;
	private final int watch_gen = 42;
	private final LinkedList<JsonObject> msgReceived = new LinkedList<>();

	/**
	 * Initialize UAOClient class
	 *
	 * @param endpoint  Server endpoint address.
	 * @param timeoutms Connection timeout.
	 * @param useSsl    True to use SSL on connection.
	 * @throws DeploymentException Failed to instantiate websocket client.
	 */
	public UAOClient(final String uri, final int timeoutms, final boolean useSsl) throws DeploymentException {
		this.endpoint = uri;
		final String wsEndpoint = String.format("ws://%s", endpoint); //$NON-NLS-1$

		this.ws = setWebsocket(wsEndpoint, timeoutms);
		setEllipticCurve();
		regenKeyPair();
	}

	/**
	 * Add more callbacks to the connection.
	 *
	 * @param listener method overwrite implemented as described in
	 *                 `WebSocketListener` interface.
	 */
	public void addListener(final WebSocketListener listener) {
		ws.addListener(listener);
	}

	/**
	 * Blocking message receive.
	 *
	 * @param timeout Timeout (milliseconds) for the wait on server message.
	 * @return Message received.
	 * @throws InterruptedException Thread interrupted while still waiting.
	 * @throws TimeoutException     Timeout waiting for the answer reached.
	 */
	private JsonObject receive(final long timeout, final long msgid) throws InterruptedException, TimeoutException {
		final long start = System.currentTimeMillis();
		long elapsed = 0;
		JsonObject correct_response = null;
		while (correct_response == null & elapsed < timeout) {
			elapsed = System.currentTimeMillis() - start;
			TimeUnit.MILLISECONDS.sleep(50);
			for (final JsonObject response : msgReceived) {
				if (msgid == response.get("reqid").getAsLong()) { //$NON-NLS-1$
					correct_response = response;
					msgReceived.remove(response);
					break;
				}
			}
		}
		if (elapsed > timeout) {
			throw new TimeoutException("Websocket receive Timeout reached"); //$NON-NLS-1$
		}
		return (correct_response);
	}

	/** Client connect action. */
	public void connect() throws WebSocketException {
		ws.connect();
	}

	/** Client disconnect action. */
	public void disconnect() {
		ws.disconnect();
	}

	/**
	 * Send json object to the server.
	 *
	 * @param payload The message to send
	 */
	@SuppressWarnings("unused")
	private void send(final JsonObject payload) {
		ws.sendText(payload.toString());
	}

	/**
	 * Send json object to the server and wait for the response with a default
	 * timeout of 2000ms.
	 *
	 * @param payload The message to send.
	 * @return The server response.
	 * @throws DeploymentException Different messages according to the context.
	 */
	private JsonObject sendAndWaitResponse(final JsonObject payload) throws DeploymentException {
		return (sendAndWaitResponse(payload, 2000));
	}

	/**
	 * Send json object to the server and wait for the response.
	 *
	 * @param json    The message to send.
	 * @param timeout Max time to wait the server for a response in ms.
	 * @return The server response.
	 * @throws DeploymentException Different messages according to the context.
	 */
	private JsonObject sendAndWaitResponse(final JsonObject payload, final int timeout) throws DeploymentException {
		ws.sendText(payload.toString());
		incrementCounters();
		try {
			final JsonObject response = receive(timeout, payload.get("reqid").getAsLong()); //$NON-NLS-1$
			return (response);
		} catch (final InterruptedException e) {
			throw new DeploymentException(
					MessageFormat.format(Messages.UAODeploymentExecutor_RequestInterrupted, e.getMessage()));
		} catch (final TimeoutException e) {
			throw new DeploymentException(Messages.UAODeploymentExecutor_ClientRequestTimeout);
		}

	}

	/** Check if connection is open. */
	public boolean isOpen() {
		return (ws.isOpen());
	}

	/**
	 * Send a status request and check if the response is OK.
	 *
	 * @return True if received a good response from the runtime
	 * @throws DeploymentException Server did not respond the requests in time.
	 */
	public boolean connectionCheck() throws DeploymentException {
		final JsonObject payload = getMessageBody("stat"); //$NON-NLS-1$
		final JsonObject response = sendAndWaitResponse(payload);
		return (checkResponse(response));
	}

	/**
	 * Perform an authentication with the runtime.
	 *
	 * @throws DeploymentException Server did not respond the requests in time.
	 */
	public synchronized boolean authenticate() throws DeploymentException {
		cmd_relrole();
		boolean check = false;
		final JsonObject result_keyxchg = cmd_keyxchg();
		parseError(result_keyxchg);
		if (checkResponse(result_keyxchg)) {
			final JsonElement pubkobj = result_keyxchg.get("pubkey"); //$NON-NLS-1$
			if (pubkobj != null) {
				final String runtimekey = pubkobj.getAsString();
				buildSharedKey(pubkey_decode(runtimekey));
			}

			final JsonObject result_auth = cmd_auth();
			parseError(result_auth);
			check = checkResponse(result_auth);
			if (check) {
				final JsonElement ticketobj = result_auth.get("ticket"); //$NON-NLS-1$
				if (ticketobj != null) {
					final byte[] ivbytes = decode(result_auth.get("authnonce").getAsString()); //$NON-NLS-1$
					ticket = decrypt(ivbytes, decode(ticketobj.getAsString()));
					session_id = result_auth.get("sessid").getAsInt(); //$NON-NLS-1$
				}
			}
		}
		return (check);
	}

	/**
	 * Send a flow controlling command to runtime. i.e. "start", "stop", "clean".
	 *
	 * @param cmd Command name.
	 */
	public synchronized void flow_command(final String cmd) throws DeploymentException {
		final byte[] iv = change_role("deploy"); //$NON-NLS-1$
		if (iv != null) {
			final JsonObject response = cmd_transition(cmd);
			cmd_relrole();
			parseError(response);
		}
	}

	/** Send a restart command */
	public synchronized void restart() throws DeploymentException {
		final byte[] iv = change_role("deploy"); //$NON-NLS-1$
		if (iv != null) {
			final JsonObject payload = getMessageBody("restart"); //$NON-NLS-1$
			payload.addProperty("reboot", Boolean.FALSE); //$NON-NLS-1$
			final JsonObject response = sendAndWaitResponse(payload);
			if (!checkResponse(response)) {
				// Rebooted Device won't answer if succeeded.
				cmd_relrole();
			}
			parseError(response);
		}
	}

	/** Send a reboot command */
	public synchronized void reboot() throws DeploymentException {
		final byte[] iv = change_role("deploy"); //$NON-NLS-1$
		if (iv != null) {
			final JsonObject payload = getMessageBody("restart"); //$NON-NLS-1$
			payload.addProperty("reboot", Boolean.TRUE); //$NON-NLS-1$
			final JsonObject response = sendAndWaitResponse(payload);
			if (!checkResponse(response)) {
				// Rebooted Device won't answer if succeeded.
				cmd_relrole();
			}
			parseError(response);
		}
	}

	/** Generate a private-public key pair. */
	public synchronized void regenKeyPair() {
		final ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(curveParams, rand);

		final ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
		keyGen.init(keyParams);
		final AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
		this.privKey = (ECPrivateKeyParameters) keyPair.getPrivate();
		this.pubKey = (ECPublicKeyParameters) keyPair.getPublic();
	}

	/**
	 * Perform a deploy operation.
	 *
	 * @param doc    XML Document.
	 * @param projId Project UUID.
	 * @param snapId Snapshot UIID.
	 * @param autoStart Flag that enables start command after deploy.
	 * @throws DeploymentException Operation failed.
	 */
	public synchronized void deploy(final Document doc, final String projId, final String snapId, final boolean autoStart)
			throws DeploymentException {
		final Map<String, byte[]> deployList = new TreeMap<>();

		MessageDigest flistHash = null;
		try {
			flistHash = MessageDigest.getInstance("SHA-256"); //$NON-NLS-1$
		} catch (final NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// TODO: Loop in all files to send. Currently only the Sys project is sent.
		final UAOBinFile binProj = new UAOBinFile(doc);
		final byte[] binProjBytes = binProj.parseToBin();
		if (flistHash != null) {
			flistHash.update(hash_sha256(binProjBytes));
		}
		deployList.put("Device.bin", binProjBytes); //$NON-NLS-1$
		// --- End Loop

		String flistHashHex = ""; //$NON-NLS-1$
		if (flistHash != null) {
			flistHashHex = Hex.encodeHexString(flistHash.digest());
		}

		final String template = "{\"snapshot\": {\"guid\": \"\",\"hash\": \"\",\"app\": {\"hash\": \"\",\"items\": [\"Device.bin\"]}}}"; //$NON-NLS-1$
		final JsonObject filelist = JsonParser.parseString(template).getAsJsonObject();
		final JsonObject snp = filelist.get("snapshot").getAsJsonObject(); //$NON-NLS-1$
		snp.addProperty("guid", snapId); //$NON-NLS-1$
		snp.addProperty("hash", flistHashHex); //$NON-NLS-1$
		snp.get("app").getAsJsonObject().addProperty("hash", flistHashHex); //$NON-NLS-1$ //$NON-NLS-2$

		deployList.put("FileList.json", filelist.toString().getBytes()); //$NON-NLS-1$

		boolean uploadOk = false;
		try {
			final List<HttpResponse> responseList = sendFiles(deployList, snapId);
			uploadOk = checkHttpResponses(responseList);
		} catch (DeploymentException | IOException e) {
			e.printStackTrace();
		}

		if (uploadOk) {
			cmd_deploy(projId, snapId);
			if (autoStart) {
				flow_command("start"); //$NON-NLS-1$
			}
		}
	}

	/**
	 * Perform a deploy operation defauting the autoStart flag to false 
	 *
	 * @param doc    XML Document.
	 * @param projId Project UUID.
	 * @param snapId Snapshot UIID.
	 * @throws DeploymentException Operation failed.
	 */
	public synchronized void deploy(final Document doc, final String projId, final String snapId)
			throws DeploymentException {
		deploy(doc, projId, snapId, false);
	}

	/**
	 * Search 'stat' response for current device state.
	 *
	 * @return Runtime state name
	 */
	public synchronized String getDeviceState() throws DeploymentException {
		final byte[] iv = change_role("deploy"); //$NON-NLS-1$
		String state = null;

		if (iv != null) {
			final JsonObject response = sendAndWaitResponse(getMessageBody("stat")); //$NON-NLS-1$
			final JsonElement stateobj = response.get("device_state"); //$NON-NLS-1$
			if (stateobj != null) {
				state = stateobj.getAsString();
			}
			cmd_relrole();
			parseError(response);
		}
		return (state);
	}

	/**
	 * Register this client as a watcher in the runtime.
	 *
	 * @return List of available resources
	 * @throws DeploymentException
	 */
	public synchronized List<String> registerAsWatcher() throws DeploymentException {
		final byte[] iv = change_role("watch"); //$NON-NLS-1$
		JsonObject response = null;
		final List<String> resList = new ArrayList<>();

		if (iv != null) {
			final JsonObject payload = getMessageBody("regwatch"); //$NON-NLS-1$
			payload.addProperty("generation", Integer.valueOf(watch_gen)); //$NON-NLS-1$
			response = sendAndWaitResponse(payload);

			cmd_relrole();
			parseError(response);
			for (final JsonElement res : response.get("resources").getAsJsonArray()) { //$NON-NLS-1$
				resList.add(res.getAsString());
			}
		}
		return (resList);
	}

	/**
	 * Register a watch item into the runtime.
	 *
	 * @param res        The name of the resource in the runtime
	 * @param entry_path The Path to the item to watch
	 * @param id         unique identifier of this watch Item
	 * @return True if the watch was registered
	 * @throws DeploymentException
	 */
	public synchronized boolean addWatch(final String res, final String entry_path, final int id)
			throws DeploymentException {
		final byte[] iv = change_role("watch"); //$NON-NLS-1$
		JsonObject response = null;

		if (iv != null) {
			final JsonObject payload = getMessageBody("regwatchitem"); //$NON-NLS-1$
			payload.addProperty("resource", res); //$NON-NLS-1$
			payload.addProperty("generation", Integer.valueOf(watch_gen)); //$NON-NLS-1$
			payload.addProperty("path", entry_path); //$NON-NLS-1$
			payload.addProperty("item_id", Integer.valueOf(id)); //$NON-NLS-1$
			response = sendAndWaitResponse(payload);
			cmd_relrole();
			parseError(response);
		}
		return (checkResponse(response));
	}

	/**
	 * Remove the registered item from the watch list in the runtime
	 *
	 * @param res The name of the resource in the runtime
	 * @param id  unique identifier of this watch Item
	 * @return True if the watch was successfully removed.
	 * @throws DeploymentException
	 */
	public synchronized boolean removeWatch(final String res, final int id) throws DeploymentException {
		final byte[] iv = change_role("watch"); //$NON-NLS-1$
		JsonObject response = null;

		if (iv != null) {
			final JsonObject payload = getMessageBody("unregwatchitem"); //$NON-NLS-1$
			payload.addProperty("resource", res); //$NON-NLS-1$
			payload.addProperty("generation", Integer.valueOf(watch_gen)); //$NON-NLS-1$
			payload.addProperty("item_id", Integer.valueOf(id)); //$NON-NLS-1$
			response = sendAndWaitResponse(payload);
			cmd_relrole();
			parseError(response);
		}
		return (checkResponse(response));
	}

	/**
	 * Ask the runtime for the registered watch values.
	 *
	 * @param res The name of the resource in the runtime i.e. "RES0" or "EMB_RES"
	 * @return A list of strings for the watch values formatted.
	 * @throws DeploymentException
	 */
	public synchronized List<String> fetchWatches(final String res) throws DeploymentException {
		final byte[] iv = change_role("watch"); //$NON-NLS-1$
		final List<String> responseList = new ArrayList<>();
		JsonObject response = null;

		if (iv != null) {
			final JsonObject payload = getMessageBody("poll"); //$NON-NLS-1$
			payload.addProperty("resource", res); //$NON-NLS-1$
			response = sendAndWaitResponse(payload);
			if (checkResponse(response)) {
				final byte[] databytes = decode(response.get("data").getAsString()); //$NON-NLS-1$
				responseList.addAll(Watches.decodeWatchData(databytes));
			}
			// NOTE: Removing the role release here speed up the watch loop
			// cmd_relrole();
			parseError(response);
		}
		return (responseList);
	}

	/**
	 * Trigger an event on the runtime
	 *
	 * @param res        The name of the resource in the runtime
	 * @param event_path The Path to the event to trigger
	 * @return True if the trigger was successful
	 * @throws DeploymentException
	 */
	public synchronized boolean triggerEvent(final String res, final String event_path) throws DeploymentException {
		final byte[] iv = change_role("watch"); //$NON-NLS-1$
		JsonObject response = null;

		if (iv != null) {
			final JsonObject payload = getMessageBody("trigger"); //$NON-NLS-1$
			payload.addProperty("resource", res); //$NON-NLS-1$
			payload.addProperty("path", event_path); //$NON-NLS-1$
			response = sendAndWaitResponse(payload);
			cmd_relrole();
			parseError(response);
		}
		return (checkResponse(response));
	}

	/**
	 * Set a value force on the runtime
	 *
	 * @param en         Enable/Disable the Force on runtime
	 * @param res        The name of the resource in the runtime
	 * @param entry_path The Path to the event to trigger
	 * @param value      The value of the entry to force
	 * @return True if the force request was successful
	 * @throws DeploymentException
	 */
	public synchronized boolean forceValue(final boolean en, final String res, final String entry_path,
			final String value) throws DeploymentException {
		final byte[] iv = change_role("watch"); //$NON-NLS-1$
		JsonObject response = null;

		final JsonObject forceData = new JsonObject();
		forceData.addProperty("enable", Boolean.valueOf(en)); //$NON-NLS-1$
		forceData.addProperty("path", entry_path); //$NON-NLS-1$
		if (value != null) {
			forceData.addProperty("value", value); //$NON-NLS-1$
		}

		if (iv != null) {
			final JsonObject payload = getMessageBody("force"); //$NON-NLS-1$
			payload.addProperty("resource", res); //$NON-NLS-1$
			payload.add("variable", forceData); //$NON-NLS-1$
			response = sendAndWaitResponse(payload);
			cmd_relrole();
			parseError(response);
		}
		return (checkResponse(response));
	}

	/**
	 * Query the runtime for existing forced values
	 *
	 * @param res The name of the resource in the runtime
	 * @return An array JsonElements of "forceData" type (see forceValue function)
	 * @throws DeploymentException
	 */
	public synchronized JsonArray forceQuery(final String res) throws DeploymentException {
		final byte[] iv = change_role("watch"); //$NON-NLS-1$
		JsonObject response = null;
		final JsonArray forceArray = new JsonArray();
		JsonObject payload;

		if (iv != null) {
			boolean firstIt = true;
			JsonArray tmpArray = new JsonArray();
			while (!tmpArray.isEmpty() | firstIt) {
				payload = getMessageBody("queryforce"); //$NON-NLS-1$
				payload.addProperty("resource", res); //$NON-NLS-1$
				payload.addProperty("first", Boolean.valueOf(firstIt)); //$NON-NLS-1$
				response = sendAndWaitResponse(payload);
				if (checkResponse(response)) {
					tmpArray = response.get("forces").getAsJsonArray(); //$NON-NLS-1$
					if (!tmpArray.isEmpty()) {
						forceArray.addAll(tmpArray);
					}
				}
				firstIt = false;
			}
			// NOTE: Removing the role release here speed up the watch loop
			// cmd_relrole();
		}
		return (forceArray);
	}

	/**
	 * Access runtime response and parse the error as an exception.
	 *
	 * @param response Runtime response.
	 * @throws DeploymentException
	 */
	@SuppressWarnings("null")
	private static void parseError(final JsonObject response) throws DeploymentException {
		if (!checkResponse(response) & response != null) {
			final int status = response.get("result").getAsInt(); //$NON-NLS-1$
			final String reason = response.get("error").getAsJsonObject().get("desc").getAsString(); //$NON-NLS-1$ //$NON-NLS-2$
			throw new DeploymentException(MessageFormat.format(Messages.UAODeploymentExecutor_RequestRejected,
					Integer.valueOf(status), reason));
		}
	}

	/**
	 * Create the websocket client.
	 *
	 * @param endpoint  Server endpoint address.
	 * @param timeoutms Connection timeout.
	 * @throws DeploymentException Failed to instantiate websocket client.
	 */
	private WebSocket setWebsocket(final String endpoint, final int timeoutms) throws DeploymentException {
		WebSocket websock = null;
		try {
			final WebSocketFactory wsFactory = new WebSocketFactory();
			if (timeoutms > 0) {
				wsFactory.setConnectionTimeout(timeoutms);
			}
			websock = wsFactory.createSocket(endpoint);
		} catch (final IOException e) {
			throw new DeploymentException(
					MessageFormat.format(Messages.UAODeploymentExecutor_CreateClientFailed, e.getMessage()));
		}

		websock.addListener(new WebSocketAdapter() {
			@Override
			public void onTextMessage(final WebSocket websocket, final String text) {
				msgReceived.add((JsonObject) JsonParser.parseString(text));
			}

			@Override
			public void onError(final WebSocket websocket, final WebSocketException cause) {
				Activator.getDefault().logError("UAOClient | Error:" + cause.getMessage()); //$NON-NLS-1$
			}
		});
		return (websock);
	}

	/** Set the Elliptic Curve configurations. */
	private void setEllipticCurve() {
		this.curveSpec = ECNamedCurveTable.getParameterSpec("secp256r1"); //$NON-NLS-1$
		this.curveParams = new ECDomainParameters(curveSpec.getCurve(), curveSpec.getG(), curveSpec.getN(),
				curveSpec.getH(), curveSpec.getSeed());
	}

	/**
	 * Build message body.
	 *
	 * @param operation The operation mode to ask the runtime.
	 */
	private JsonObject getMessageBody(final String operation) {
		final JsonObject payload = new JsonObject();
		payload.addProperty("op", operation); //$NON-NLS-1$
		payload.addProperty("msgnr", Integer.valueOf(msgnr)); //$NON-NLS-1$
		payload.addProperty("reqid", Integer.valueOf(reqid)); //$NON-NLS-1$
		return (payload);
	}

	/**
	 * Check for response status.
	 *
	 * @param response Server response.
	 * @return True if the response has status 200.
	 */
	private static boolean checkResponse(final JsonObject response) {
		boolean isok = false;
		if (response != null) {
			final JsonElement resobj = response.get("result"); //$NON-NLS-1$
			if (resobj != null) {
				isok = resobj.getAsInt() == 200;
			}
		}
		return (isok);
	}

	/**
	 * Get the encryption algorithm
	 *
	 * @param mode Can be `Cipher.ENCRYPT_MODE` and `Cipher.DECRYPT_MODE`
	 * @param iv   Random number.
	 * @return Encryption algorithm
	 */
	private Cipher getCipher(final int mode, final byte[] iv) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC"); //$NON-NLS-1$ //$NON-NLS-2$
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			Activator.getDefault().logError("Cipher Instance failed. Message: " + e.getMessage()); //$NON-NLS-1$
            e.printStackTrace();
		} // Dummy Exception catch

		final SecretKeySpec key = new SecretKeySpec(sharedSecret, "AES"); //$NON-NLS-1$
		final IvParameterSpec param = new IvParameterSpec(iv);
		if (cipher != null) {
			try {
				cipher.init(mode, key, param);
			} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                Activator.getDefault().logError("Cipher Initialization failed. Message: " + e.getMessage()); //$NON-NLS-1$
				e.printStackTrace();
			} // Dummy Exception catch
		}

		return (cipher);
	}

	/**
	 * Encrypt giver bytes.
	 *
	 * @param iv   Random number.
	 * @param data Bytes to encrypt.
	 * @return Encrypted bytes
	 */
	private byte[] encrypt(final byte[] iv, final byte[] data) {
		final Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, iv);
		byte[] data_encryp = null;
		try {
			data_encryp = cipher.doFinal(data);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

		return (data_encryp);
	}

	/**
	 * Decrypt given bytes.
	 *
	 * @param iv          Random number.
	 * @param data_encryp Encrypted bytes.
	 * @return normal bytes
	 */
	private byte[] decrypt(final byte[] iv, final byte[] data_encryp) {
		final Cipher cipher = getCipher(Cipher.DECRYPT_MODE, iv);
		byte[] data = null;
		try {
			data = cipher.doFinal(data_encryp);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

		return (data);
	}

	/** Increment message counter. */
	private void incrementCounters() {
		msgnr += 1;
		reqid += 1;
	}

	/**
	 * Decode an elliptic curve Public Key.
	 *
	 * @param public_key_encoded The encoded key.
	 * @return Public Key.
	 */
	private ECPublicKeyParameters pubkey_decode(final String public_key_encoded) {
		final byte[] public_key_data = decode(public_key_encoded);
		final ECPublicKeyParameters public_key = new ECPublicKeyParameters(
				curveSpec.getCurve().decodePoint(public_key_data), curveParams);
		return (public_key);
	}

	/**
	 * Decode an elliptic curve Private Key.
	 *
	 * @param private_key_encoded The encoded key.
	 * @return Private Key.
	 */
	@SuppressWarnings("unused")
	private ECPrivateKeyParameters privkey_decode(final String private_key_encoded) {
		final byte[] private_key_data = decode(private_key_encoded);
		final BigInteger private_key_int = new BigInteger(private_key_data);
		final ECPrivateKeyParameters private_key = new ECPrivateKeyParameters(private_key_int, curveParams);
		return (private_key);
	}

	/**
	 * Encode an elliptic curve Public Key.
	 *
	 * @param public_key The key.
	 * @return Public Key encoded string.
	 */
	private static String pubkey_encode(final ECPublicKeyParameters public_key) {
		return (encode(public_key.getQ().getEncoded(false)));
	}

	/**
	 * Encode an elliptic curve Private Key.
	 *
	 * @param private_key The key.
	 * @return Private Key encoded string.
	 */
	@SuppressWarnings("unused")
	private static String privkey_encode(final ECPrivateKeyParameters private_key) {
		return (encode(private_key.getD().toByteArray()));
	}

	/**
	 * Decode string to bytes.
	 *
	 * @param datab64 Base64 bytes as string.
	 * @return Data in bytes.
	 */
	private static byte[] decode(final String datab64) {
		final byte[] databyte = Base64.getDecoder().decode(datab64);
		return (databyte);
	}

	/**
	 * Encode bytes into string.
	 *
	 * @param databyte Data in bytes.
	 * @return Base64 bytes as string.
	 */
	private static String encode(final byte[] databyte) {
		final String datab64 = Base64.getEncoder().encodeToString(databyte);
		return (datab64);
	}

	/**
	 * Hash bytes with SHA256 algorithm.
	 *
	 * @param data Bytes.
	 * @return Hashed bytes.
	 */
	private static byte[] hash_sha256(final byte[] data) {
		MessageDigest hashinstance = null;
		try {
			hashinstance = MessageDigest.getInstance("SHA-256"); //$NON-NLS-1$
		} catch (final NoSuchAlgorithmException e) {
			e.printStackTrace();
		} // Dummy Exception catch
		byte[] hashData = null;
		if (hashinstance != null) {
			hashData = hashinstance.digest(data);
		}
		return (hashData);
	}

	/**
	 * Build a shared secret between their key and ours
	 *
	 * @param public_key received key.
	 */
	private void buildSharedKey(final ECPublicKeyParameters public_key) {
		final ECDHBasicAgreement keyAg = new ECDHBasicAgreement();
		keyAg.init(privKey);
		final byte[] aggrement = keyAg.calculateAgreement(public_key).toByteArray();

		sharedSecret = hash_sha256(aggrement);
	}

	/**
	 * Call 'keyxchg' command on the runtime
	 *
	 * @return runtime response
	 */
	private JsonObject cmd_keyxchg() throws DeploymentException {
		final JsonObject payload = getMessageBody("keyxchg"); //$NON-NLS-1$
		payload.addProperty("pubkey", pubkey_encode(pubKey)); //$NON-NLS-1$
		final JsonObject response = sendAndWaitResponse(payload);
		parseError(response);

		return (response);
	}

	/**
	 * Call 'auth' command on the runtime
	 *
	 * @return runtime response
	 */
	private JsonObject cmd_auth() throws DeploymentException {
		final JsonObject payload = getMessageBody("auth"); //$NON-NLS-1$

		final byte[] ivbytes = new byte[16];
		rand.nextBytes(ivbytes);

		final JsonObject cred = new JsonObject();
		final byte[] encrypted_creds = encrypt(ivbytes, cred.toString().getBytes());

		final JsonObject back = new JsonObject();
		back.addProperty("method", "anonymous"); //$NON-NLS-1$ //$NON-NLS-2$
		payload.addProperty("authnonce", encode(ivbytes)); //$NON-NLS-1$
		payload.add("backend", back); //$NON-NLS-1$
		payload.addProperty("credentials", encode(encrypted_creds)); //$NON-NLS-1$

		final JsonObject response = sendAndWaitResponse(payload);
		parseError(response);

		return (response);
	}

	/**
	 * Calculate the HMAC algorithm on a message
	 *
	 * @param message Byte message.
	 * @return The message with HMAC.
	 */
	private byte[] calculateHmac(final byte[] message) {
		Mac sha256_HMAC = null;
		try {
			sha256_HMAC = Mac.getInstance("HmacSHA256"); //$NON-NLS-1$
		} catch (final NoSuchAlgorithmException e) {
			e.printStackTrace();
		} // Dummy Exception catch

		final SecretKeySpec key = new SecretKeySpec(ticket, "HmacSHA256"); //$NON-NLS-1$

		byte[] hmac = null;
		if (sha256_HMAC != null) {
			try {
				sha256_HMAC.init(key);
			} catch (final InvalidKeyException e) {
				e.printStackTrace();
			} // Dummy Exception catch

			hmac = sha256_HMAC.doFinal(message);
		}

		return (hmac);
	}

	/**
	 * Call 'rqnonce' command on the runtime.
	 *
	 * @param role.
	 * @return runtime response
	 */
	private JsonObject cmd_rqnonce(final String role) throws DeploymentException {
		final JsonObject payload = getMessageBody("rqnonce"); //$NON-NLS-1$
		payload.addProperty("role", role); //$NON-NLS-1$

		final JsonObject response = sendAndWaitResponse(payload);
		parseError(response);
		return (response);
	}

	/**
	 * Call 'rqrole' command on the runtime.
	 *
	 * @param role.
	 * @param iv    Random number.
	 * @return runtime response
	 */
	private JsonObject cmd_rqrole(final String role, final byte[] iv) throws DeploymentException {
		final JsonObject payload = getMessageBody("rqrole"); //$NON-NLS-1$
		payload.addProperty("role", role); //$NON-NLS-1$
		payload.addProperty("sessid", Integer.valueOf(session_id)); //$NON-NLS-1$
		payload.addProperty("hmac", encode(calculateHmac(iv))); //$NON-NLS-1$

		final JsonObject response = sendAndWaitResponse(payload);
		parseError(response);
		return (response);
	}

	/**
	 * Execute the change role steps.
	 *
	 * @param role.
	 * @return A number received.
	 */
	private synchronized byte[] change_role(final String role) throws DeploymentException {
		if (role.equals(current_role)) {
			return (current_role_iv);
		}
		final JsonObject nonce_result = cmd_rqnonce(role);

		if (checkResponse(nonce_result)) {
			final JsonElement nonceobj = nonce_result.get("nonce"); //$NON-NLS-1$
			if (nonceobj != null) {
				final byte[] ivbytes = decode(nonceobj.getAsString());

				final JsonObject role_result = cmd_rqrole(role, ivbytes);
				parseError(role_result);
				if (checkResponse(role_result)) {
					current_role = role;
					current_role_iv = ivbytes;
					return (ivbytes);
				}
			}
		}
		return (null);
	}

	/**
	 * Call 'relrole' command on the runtime.
	 *
	 * @return runtime response
	 */
	private JsonObject cmd_relrole() throws DeploymentException {
		final JsonObject payload = getMessageBody("relrole"); //$NON-NLS-1$
		final JsonObject response = sendAndWaitResponse(payload);
		parseError(response);
		if (checkResponse(response)) {
			current_role = ""; //$NON-NLS-1$
			current_role_iv = null;
		}
		return (response);
	}

	/**
	 * Call 'transition' command on the runtime.
	 *
	 * @param cmd Flow command to execute. i.e 'start','stop','clean' ...
	 * @return runtime response
	 */
	private JsonObject cmd_transition(final String cmd) throws DeploymentException {
		final JsonObject payload = getMessageBody("transition"); //$NON-NLS-1$
		payload.addProperty("command", cmd); //$NON-NLS-1$
		final JsonObject response = sendAndWaitResponse(payload);
		parseError(response);
		return (response);
	}

	/**
	 * Call 'deploy' command on the runtime.
	 *
	 * @param projId UUID for the project.
	 * @param snapId UUID for the deploy.
	 * @return runtime response
	 */
	private synchronized JsonObject cmd_deploy(final String projId, final String snapId) throws DeploymentException {
		final byte[] iv = change_role("deploy"); //$NON-NLS-1$
		JsonObject response = null;

		if (iv != null) {
			final JsonObject payload = getMessageBody("transition"); //$NON-NLS-1$
			payload.addProperty("command", "deploy"); //$NON-NLS-1$ //$NON-NLS-2$
			payload.addProperty("project_guid", projId); //$NON-NLS-1$
			payload.addProperty("snapshot_guid", snapId); //$NON-NLS-1$

			response = sendAndWaitResponse(payload);
			cmd_relrole();
			parseError(response);
		}

		return (response);
	}

	/**
	 * Send a list of files to the Runtime.
	 *
	 * @param fileMap a Filename:Filebytes kind of map.
	 * @param snpId   Snapshot UUID.
	 * @return List of Http responses.
	 * @throws DeploymentException Runtime failed to respond.
	 */
	private synchronized List<HttpResponse> sendFiles(final Map<String, byte[]> fileMap, final String snpId)
			throws DeploymentException, ClientProtocolException, IOException {
		final String httpEndpoint = String.format("http://%s/upload/", endpoint); //$NON-NLS-1$

		final CloseableHttpClient httpClient = HttpClients.createDefault();
		final BasicCookieStore cookieStore = new BasicCookieStore();
		final BasicHttpContext httpContext = new BasicHttpContext();
		httpContext.setAttribute(HttpClientContext.COOKIE_STORE, cookieStore);

		final List<HttpResponse> responseList = new ArrayList<>();

		final byte[] iv = change_role("deploy"); //$NON-NLS-1$
		if (iv != null) {
			int n = 0;
			for (final Map.Entry<String, byte[]> file : fileMap.entrySet()) {
				n++;

				final byte[] nbytes = UAOBinFile.write_word(n, ByteOrder.BIG_ENDIAN);
				final byte[] concat = ByteBuffer.allocate(iv.length + nbytes.length).put(iv).put(nbytes).array();
				final String hmac = encode(calculateHmac(concat));
				final String filehash = Hex.encodeHexString(hash_sha256(file.getValue()));

				final MultipartEntityBuilder entity = MultipartEntityBuilder.create();
				entity.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
				entity.addBinaryBody(file.getKey(), file.getValue(), ContentType.DEFAULT_BINARY, file.getKey());

				final Integer flen = Integer.valueOf(file.getValue().length);
				final RequestBuilder request = RequestBuilder.put(httpEndpoint);
				request.setEntity(entity.build());
				request.addHeader("Accept", "*/*"); //$NON-NLS-1$ //$NON-NLS-2$
				final String auth = String.format("session-id=%d;nonce=\"%s\";counter=%d;hmac=\"%s\"", //$NON-NLS-1$
						Integer.valueOf(session_id), encode(iv), Integer.valueOf(n), hmac);
				final String xfer = String.format(
						"filesize=\"%d\" ;directory=\"Working\"; hash=\"%s\"; snapshot-guid=\"%s\"", flen, filehash, //$NON-NLS-1$
						snpId);
				request.addHeader("SRT61499N-Auth", auth); //$NON-NLS-1$
				request.addHeader("SRT61499N-Xfer", xfer); //$NON-NLS-1$

				final HttpUriRequest multipartRequest = request.build();

				responseList.add(httpClient.execute(multipartRequest, httpContext));
			}
		}
		return (responseList);
	}

	/**
	 * Check if all Http responses have status 200
	 *
	 * @param responseList a List of HttpResponse objects.
	 * @return True is is all 200.
	 */
	private static boolean checkHttpResponses(final List<HttpResponse> responseList) {
		boolean check = true;
		for (final HttpResponse response : responseList) {
			check = check && response.getStatusLine().getStatusCode() == 200;
		}
		return (check);
	}

}
