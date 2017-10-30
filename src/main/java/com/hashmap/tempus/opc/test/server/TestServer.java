/*
 * Copyright (c) 2016 Kevin Herron
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *   http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.html.
 */

package com.hashmap.tempus.opc.test.server;

import java.io.File;
import java.util.EnumSet;
import java.util.concurrent.ExecutionException;

import com.google.common.collect.ImmutableList;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.eclipse.milo.opcua.stack.core.application.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.application.DefaultCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.types.structured.ResponseHeader;
import org.eclipse.milo.opcua.stack.core.types.structured.TestStackExRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.TestStackExResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.TestStackRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.TestStackResponse;
import org.eclipse.milo.opcua.stack.core.util.CryptoRestrictions;
import org.slf4j.LoggerFactory;

import static com.google.common.collect.Lists.newArrayList;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_USERNAME;

public class TestServer {

    /**
     * Starts the OPC UA Server
     */
    public void start(){
        try {
            server.startup().get();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    /**
     * Stops the OPC UA Server
     */
    public void stop(){
        try {
            server.shutdown().get();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    private final OpcUaServer server;

    /**
     * Creates the OPC UA Server that will listen on the specified port
     * @param port The port that the OPC server will listen on
     * @throws Exception Will be thrown if there is an error configuring the OPC UA server
     */
    public TestServer(int port) throws Exception {
        CryptoRestrictions.remove();

        KeyStoreLoader loader = new KeyStoreLoader().load();

        DefaultCertificateManager certificateManager = new DefaultCertificateManager(
            loader.getServerKeyPair(),
            loader.getServerCertificate()
        );

        File securityTempDir = new File(System.getProperty("java.io.tmpdir"), "security");

        LoggerFactory.getLogger(getClass())
            .info("security temp dir: {}", securityTempDir.getAbsolutePath());

        DefaultCertificateValidator certificateValidator = new DefaultCertificateValidator(securityTempDir);

        UsernameIdentityValidator identityValidator = new UsernameIdentityValidator(
            true,
            authChallenge -> {
                String username = authChallenge.getUsername();
                String password = authChallenge.getPassword();

                boolean userOk = "user".equals(username) && "password1".equals(password);
                boolean adminOk = "admin".equals(username) && "password2".equals(password);
            
                return userOk || adminOk;
            }
        );

        OpcUaServerConfig serverConfig = OpcUaServerConfig.builder()
            .setApplicationUri("urn:hashmap:opc:test-server")
            .setApplicationName(LocalizedText.english("OPC-UA Test Server"))
            .setBindAddresses(newArrayList("0.0.0.0"))
            .setBindPort(port)
            .setBuildInfo(
                new BuildInfo(
                    "urn:hashmap:opc:test-server",
                    "eclipse",
                    "OPC Test Server",
                    OpcUaServer.SDK_VERSION,
                    "", DateTime.now()))
            .setCertificateManager(certificateManager)
            .setCertificateValidator(certificateValidator)
            .setIdentityValidator(identityValidator)
            .setProductUri("urn:hashmap:opc:test-server")
            .setServerName("test")
            .setSecurityPolicies(
                EnumSet.of(
                    SecurityPolicy.None,
                    SecurityPolicy.Basic128Rsa15,
                    SecurityPolicy.Basic256,
                    SecurityPolicy.Basic256Sha256))
            .setUserTokenPolicies(
                ImmutableList.of(
                    USER_TOKEN_POLICY_ANONYMOUS,
                    USER_TOKEN_POLICY_USERNAME))
            .build();

        server = new OpcUaServer(serverConfig);

        server.getNamespaceManager().registerAndAdd(
            ExampleNamespace.NAMESPACE_URI,
            idx -> new ExampleNamespace(server, idx));

        server.getServer().addRequestHandler(TestStackRequest.class, service -> {
            TestStackRequest request = service.getRequest();

            ResponseHeader header = service.createResponseHeader();

            service.setResponse(new TestStackResponse(header, request.getInput()));
        });

        server.getServer().addRequestHandler(TestStackExRequest.class, service -> {
            TestStackExRequest request = service.getRequest();

            ResponseHeader header = service.createResponseHeader();

            service.setResponse(new TestStackExResponse(header, request.getInput()));
        });
    }
}
