package jadx.plugins.decompiler;

import java.io.File;
import java.io.StringReader;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.xml.parsers.DocumentBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import jadx.api.ResourceFile;
import jadx.api.metadata.ICodeNodeRef;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.utils.android.AndroidManifestParser;
import jadx.core.utils.exceptions.JadxRuntimeException;
import jadx.core.xmlgen.XmlSecurity;

public class EvalMethod implements JadxPlugin {
	public static final String PLUGIN_ID = "jadx-eval-method";
	private static final Logger LOG = LoggerFactory.getLogger(EvalMethod.class);
	private final EvalMethodOptions options = new EvalMethodOptions();
	private final EvalMethodPass pass = new EvalMethodPass();
	private JadxPluginContext context;
	private String packageName = null;
	private ResourceFile androidManifest = null;
	private final ExecutorService executor;

	public EvalMethod() {
		this.executor = Executors.newSingleThreadExecutor();
	}

	@Override
	public JadxPluginInfo getPluginInfo() {
		return new JadxPluginInfo(PLUGIN_ID, "Jadx Eval Method",
				"Evaluate methods in runtime (powered by Frida) and update the decompiler output.");
	}

	@Override
	public void init(JadxPluginContext context) {
		LOG.info("init");
		this.context = context;
		context.registerOptions(options);

		if (context.getGuiContext() == null) {
			LOG.info("missing gui context");
			return;
		}

		try {
			pass.fridaProxy = new FridaProxy(options.getFridaProxyHost(), options.getFridaProxyPort());
		} catch (Exception e) {
			LOG.error("failed to create FridaProxy", e);
			return;
		}

		List<File> inputs = context.getArgs().getInputFiles();
		if (inputs.isEmpty()) {
			LOG.error("no input files");
			return;
		} else if (inputs.size() > 1) {
			LOG.warn("more than one input file, choosing the first one");
		}

		LOG.info("installing package");
		try {
			pass.fridaProxy.installPackage(inputs.get(0).getAbsolutePath());
		} catch (Exception e) {
			LOG.error("Failed to install the package, plugin will be disabled.");
			return;
		}

		LOG.info("adding plugin pass");
		context.addPass(pass);

		context.getGuiContext().addPopupMenuAction(
				"Add method to eval targets",
				(ICodeNodeRef node) -> options.isEnable() && node instanceof MethodNode,
				"G",
				(ICodeNodeRef node) -> run(node));

		this.executor.submit(() -> {
			while (androidManifest == null) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					LOG.error("interrupted while waiting for AndroidManifest.xml");
				}

				androidManifest = AndroidManifestParser
						.getAndroidManifest(context.getDecompiler().getResources());
			}

			String xmlContent;
			while (true) {
				try {
					Thread.sleep(500);
				} catch (InterruptedException e) {
					LOG.error("interrupted while waiting for AndroidManifest.xml");
				}

				try {
					xmlContent = androidManifest.loadContent().getText().getCodeStr();
				} catch (Exception e) {
					LOG.error("failed to load AndroidManifest.xml");
					continue;
				}
				break;
			}

			try {
				DocumentBuilder builder = XmlSecurity.getDBF().newDocumentBuilder();
				Document document = builder.parse(new InputSource(new StringReader(xmlContent)));
				document.getDocumentElement().normalize();
				packageName = document.getDocumentElement().getAttribute("package");
				if (packageName.isEmpty()) {
					LOG.error("no package name found in AndroidManifest.xml");
				}
			} catch (Exception e) {
				throw new JadxRuntimeException("Can not parse xml content", e);
			}

			LOG.info("package name: {}", packageName);
			pass.packageName = packageName;

			LOG.info("plugin is ready");
			options.setEnable(true);
		});
	}

	private void run(ICodeNodeRef node) {
		this.pass.addTarget(((MethodNode) node).getMethodInfo().getRawFullId());
		this.context.getGuiContext().reloadActiveTab();
	}
}
