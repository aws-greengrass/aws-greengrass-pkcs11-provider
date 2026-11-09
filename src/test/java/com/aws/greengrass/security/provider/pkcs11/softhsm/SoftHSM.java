/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.pkcs11.softhsm;

import com.aws.greengrass.config.PlatformResolver;
import com.aws.greengrass.security.provider.pkcs11.PKCS11CryptoKeyService;
import com.aws.greengrass.security.provider.pkcs11.exceptions.ProviderInstantiationException;
import com.aws.greengrass.util.Exec;
import com.aws.greengrass.util.platforms.Platform;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.IOFileFilter;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_CLASS;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_ID;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_LABEL;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_RW_SESSION;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_SERIAL_SESSION;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKO_PRIVATE_KEY;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKU_USER;

public class SoftHSM {
    // Defined locally because JDK 17 moved it from PKCS11Constants to PKCS11Exception
    private static final long CKR_USER_ALREADY_LOGGED_IN = 0x00000100L;
    private static final String SOFTHSM_TOKEN_DIRECTORY;
    private static final List<String> SOFTHSM_INSTALL_DIRECTORY;
    private static final String SOFTHSM_SHARED_LIBRARY_FILE_NAME = "libsofthsm2.so";
    private static final String SOFTHSM_SO_PIN = "12345";
    private static final Pattern SLOT_ID_PATTERN = Pattern.compile("initialized\\s*.+\\s*slot\\s([0-9]+)");
    private static final Path USUAL_LINUX_LOCATION = Paths.get("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so");

    static {
        if ("darwin".equals(PlatformResolver.getOSInfo())) {
            SOFTHSM_TOKEN_DIRECTORY = "/usr/local/var/lib/softhsm/tokens";
            SOFTHSM_INSTALL_DIRECTORY = Collections.singletonList("/usr/local/Cellar/");
        } else {
            SOFTHSM_TOKEN_DIRECTORY = "/var/lib/softhsm/tokens";
            SOFTHSM_INSTALL_DIRECTORY = Arrays.asList("/usr/lib/", "/usr/lib64/");
        }
    }

    private final Path sharedLibraryPath;

    public SoftHSM() {
        try {
            sharedLibraryPath = findSoftHSMSharedLibrary();
            verifySoftHSMSetup();
        } catch (IOException e) {
            throw new RuntimeException("Failed to verify SoftHSM setup on the device", e);
        }
    }

    public Path getSharedLibraryPath() {
        return sharedLibraryPath;
    }

    public HSMToken initToken(HSMToken hsmToken) {
        String cmd;
        if (hsmToken.getSlotId() < 0) {
            cmd = String.format("softhsm2-util --init-token --free --label %s --so-pin %s --pin %s",
                    hsmToken.getLabel(), SOFTHSM_SO_PIN, hsmToken.getUserPin());
        } else {
            cmd = String.format("softhsm2-util --init-token --slot %d --label %s --so-pin %s --pin %s",
                    hsmToken.getSlotId(), hsmToken.getLabel(), SOFTHSM_SO_PIN, hsmToken.getUserPin());
        }

        AtomicInteger slotId = new AtomicInteger();
        runCmd(cmd, out -> {
            Matcher m = SLOT_ID_PATTERN.matcher(out);
            if (m.find()) {
                slotId.set(Integer.parseInt(m.group(1)));
            } else {
                throw new RuntimeException(out.toString());
            }
        }, "Failed to init token");

        return hsmToken.toBuilder().slotId(slotId.get()).build();
    }

    public void importPrivateKey(PrivateKey pKey, Certificate[] certChain, String keyLabel, HSMToken token)
            throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
            ProviderInstantiationException {
        Provider provider = PKCS11CryptoKeyService.createNewProvider(buildConfiguration(token));
        KeyStore ks = KeyStore.getInstance("PKCS11", provider);
        ks.load(null, token.getUserPin().toCharArray());
        ks.setKeyEntry(keyLabel, pKey, token.getUserPin().toCharArray(), certChain);
    }

    /**
     * Set the label of a private key imported by {@link #importPrivateKey}, so that it keeps its certificate's
     * CKA_ID but not its CKA_LABEL, like the objects that YubiKey's PKCS11 library exposes. SunPKCS11 sets
     * CKA_ID to the alias on both objects, but sets CKA_LABEL only on the certificate.
     */
    public void setPrivateKeyLabel(String keyId, String label, HSMToken token) throws IOException, PKCS11Exception {
        PKCS11 pkcs11 = PKCS11.getInstance(sharedLibraryPath.toString(), "C_GetFunctionList", null, false);
        long session = pkcs11.C_OpenSession(token.getSlotId(), CKF_SERIAL_SESSION | CKF_RW_SESSION, null, null);
        try {
            try {
                pkcs11.C_Login(session, CKU_USER, token.getUserPin().toCharArray());
            } catch (PKCS11Exception e) {
                if (e.getErrorCode() != CKR_USER_ALREADY_LOGGED_IN) {
                    throw e;
                }
            }
            pkcs11.C_FindObjectsInit(session, new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(CKA_CLASS, CKO_PRIVATE_KEY),
                    new CK_ATTRIBUTE(CKA_ID, keyId)});
            long[] handles = pkcs11.C_FindObjects(session, 2);
            pkcs11.C_FindObjectsFinal(session);
            if (handles.length != 1) {
                throw new IllegalStateException(String.format("Expected one private key with id %s, found %d",
                        keyId, handles.length));
            }
            pkcs11.C_SetAttributeValue(session, handles[0], new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(CKA_LABEL, label)});
        } finally {
            pkcs11.C_CloseSession(session);
        }
    }

    public boolean containKey(String keyLabel, HSMToken token)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
            ProviderInstantiationException {
        Provider provider = PKCS11CryptoKeyService.createNewProvider(buildConfiguration(token));
        KeyStore ks = KeyStore.getInstance("PKCS11", provider);
        ks.load(null, token.getUserPin().toCharArray());

        return ks.containsAlias(keyLabel);
    }

    public void cleanUpTokens() throws IOException {
        FileUtils.cleanDirectory(new File(SOFTHSM_TOKEN_DIRECTORY));
    }

    private void verifySoftHSMSetup() throws IOException {
        if (Files.notExists(sharedLibraryPath)) {
            throw new RuntimeException(
                    String.format("SoftHSM shared library does not exist at location: %s", sharedLibraryPath));
        }

        File softHSMTokenDirectory = new File(SOFTHSM_TOKEN_DIRECTORY);
        if (!softHSMTokenDirectory.exists() && !softHSMTokenDirectory.mkdirs()) {
            throw new RuntimeException(
                    String.format("SoftHSM token directory does not exist: %s", SOFTHSM_TOKEN_DIRECTORY));
        }

        FileUtils.cleanDirectory(softHSMTokenDirectory);
    }

    private Path findSoftHSMSharedLibrary() {
        if (Files.exists(USUAL_LINUX_LOCATION)) {
            return USUAL_LINUX_LOCATION;
        }
        for (String usrLibDirectory : SOFTHSM_INSTALL_DIRECTORY) {
            IOFileFilter fileFilter = FileFilterUtils.nameFileFilter(SOFTHSM_SHARED_LIBRARY_FILE_NAME);
            IOFileFilter dirFilter = FileFilterUtils.notFileFilter(FileFilterUtils.nameFileFilter("Python.framework"));
            Collection<File> fileList;
            try {
                fileList = FileUtils.listFiles(new File(usrLibDirectory), fileFilter, dirFilter);
            } catch (IllegalArgumentException e) {
                // directory may not exist
                continue;
            }
            if (!fileList.isEmpty()) {
                return Paths.get(fileList.iterator().next().getAbsolutePath());
            }
        }
        throw new RuntimeException(String.format("SoftHSM shared library does not exist at locations: %s",
                String.join(", ", SOFTHSM_INSTALL_DIRECTORY)));
    }

    private void runCmd(String cmd, Consumer<CharSequence> out, String msg) {
        try (Exec exec = Platform.getInstance().createNewProcessRunner()) {
            StringBuilder output = new StringBuilder();
            StringBuilder error = new StringBuilder();
            Optional<Integer> exit = exec.withExec(cmd.split(" ")).withShell().withOut(o -> {
                out.accept(o);
                output.append(o);
            }).withErr(error::append).exec();
            if (!exit.isPresent() || exit.get() != 0) {
                throw new RuntimeException(
                        String.format("%s - command: %s, output: %s , error: %s ", msg, cmd, output, error));
            }
        } catch (InterruptedException | IOException e) {
            throw new RuntimeException(String.format("%s , command : %s", msg, cmd), e);
        }
    }

    private String buildConfiguration(HSMToken hsmToken) {
        return "name=" + hsmToken.getName() + System.lineSeparator() + "library=" + sharedLibraryPath.toString()
                + System.lineSeparator() + "slot=" + hsmToken.getSlotId();
    }
}
