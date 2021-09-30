package com.aws.greengrass.security.provider.pkcs11.softhsm;

import com.aws.greengrass.config.PlatformResolver;
import com.aws.greengrass.util.Exec;
import com.aws.greengrass.util.platforms.Platform;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.IOFileFilter;
import sun.security.pkcs11.SunPKCS11;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
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

public class SoftHSM {
    private static final String SOFTHSM_TOKEN_DIRECTORY ;
    private static final List<String> SOFTHSM_INSTALL_DIRECTORY;
    private static final String SOFTHSM_SHARED_LIBRARY_FILE_NAME = "libsofthsm2.so";
    private static final String SOFTHSM_SO_PIN = "12345";
    private static final Pattern SLOT_ID_PATTERN = Pattern.compile("initialized\\s*.+\\s*slot\\s([0-9]+)");

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
            throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
        Provider provider;
        try (InputStream configStream = new ByteArrayInputStream(buildConfiguration(token).getBytes())) {
            provider = new SunPKCS11(configStream);
        }
        KeyStore ks = KeyStore.getInstance("PKCS11", provider);
        ks.load(null, token.getUserPin().toCharArray());
        ks.setKeyEntry(keyLabel, pKey, token.getUserPin().toCharArray(), certChain);
    }

    public boolean containKey(String keyLabel, HSMToken token)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        Provider provider;
        try (InputStream configStream = new ByteArrayInputStream(buildConfiguration(token).getBytes())) {
            provider = new SunPKCS11(configStream);
        }
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
