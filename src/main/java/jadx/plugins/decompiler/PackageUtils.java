package jadx.plugins.decompiler;

import java.io.File;
import java.io.StringReader;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.xml.parsers.DocumentBuilder;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.ResourceFile;
import jadx.api.plugins.JadxPluginContext;
import jadx.core.utils.android.AndroidManifestParser;
import jadx.core.xmlgen.XmlSecurity;

public class PackageUtils {
    private static final Logger LOG = LoggerFactory.getLogger(PackageUtils.class);

    private ResourceFile androidManifest = null;
    private final JadxPluginContext context;
    private final FridaProxy fridaProxy;
    private boolean isAppInstalled = false;
    private String packageName = null;

    PackageUtils(JadxPluginContext context, FridaProxy fridaProxy) {
        this.context = context;
        this.fridaProxy = fridaProxy;

        // Trigger the installation of the app on a seperate thread because the logic is
        // currently synchronous.
        LOG.info("Triggering app installation");
        Executors.newFixedThreadPool(1).submit(() -> installApp());
    }

    public boolean isAppInstalled() {
        return isAppInstalled;
    }

    public String getPackageName() {
        if (packageName == null) {
            packageName = getPackageNameImpl();
        }

        return packageName;
    }

    private String getPackageNameImpl() {
        androidManifest = AndroidManifestParser
                .getAndroidManifest(context.getDecompiler().getResources());

        if (androidManifest == null) {
            LOG.error("AndroidManifest.xml not found");
            return null;
        }

        String xmlContent;
        try {
            xmlContent = androidManifest.loadContent().getText().getCodeStr();
        } catch (Exception e) {
            LOG.error("failed to load AndroidManifest.xml: {}", e.getMessage());
            return null;
        }

        String packageName = null;
        try {
            DocumentBuilder builder = XmlSecurity.getDBF().newDocumentBuilder();
            Document document = builder.parse(new InputSource(new StringReader(xmlContent)));
            document.getDocumentElement().normalize();
            packageName = document.getDocumentElement().getAttribute("package");
        } catch (Exception e) {
            LOG.error("Can not parse xml content: {}", e);
            return null;
        }

        if (packageName.isEmpty()) {
            LOG.error("no package name found in AndroidManifest.xml");
        }

        LOG.info("package name: {}", packageName);
        return packageName;
    }

    private void installApp() {
        List<File> inputs = context.getArgs().getInputFiles();
        if (inputs.isEmpty()) {
            LOG.error("No input files found.");
            return;
        } else if (inputs.size() > 1) {
            LOG.warn("more than one input file, choosing the first one");
        }

        try {
            fridaProxy.installPackage(inputs.get(0).getAbsolutePath());
        } catch (Exception e) {
            LOG.error("Failed to install the package: {}", e.getMessage());
            return;
        }

        isAppInstalled = true;
    }
}
