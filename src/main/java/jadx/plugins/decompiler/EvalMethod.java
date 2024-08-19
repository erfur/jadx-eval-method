package jadx.plugins.decompiler;

import jadx.api.ResourceFile;
import jadx.api.metadata.ICodeNodeRef;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.api.plugins.events.JadxEventType;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.utils.android.AndroidManifestParser;
import jadx.core.utils.android.AppAttribute;
import jadx.core.utils.android.ApplicationParams;
import jadx.core.utils.exceptions.JadxRuntimeException;
import jadx.core.xmlgen.XmlSecurity;

import java.io.File;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.xml.parsers.DocumentBuilder;

import java.nio.file.Paths;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import com.google.rpc.context.AttributeContext.Resource;

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

		if (options.getScriptPath().isEmpty()) {
			LOG.error("no script path");
			return;
		}

		FridaProxy fridaProxy = new FridaProxy("%s/main.py".formatted(options.getScriptPath()));

		List<File> inputs = context.getArgs().getInputFiles();
		if (inputs.isEmpty()) {
			LOG.error("no input files");
			return;
		} else if (inputs.size() > 1) {
			LOG.error("more than one input file, choosing the first one");
		}

		LOG.info("installing package");
		fridaProxy.installPackage(inputs.get(0).getAbsolutePath());
		pass.fridaProxy = fridaProxy;

		LOG.info("adding plugin pass");
		context.addPass(pass);

		context.getGuiContext().addPopupMenuAction(
				"Add method to eval targets",
				(ICodeNodeRef node) -> enabled(node),
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
		});
	}

	private boolean enabled(ICodeNodeRef node) {
		return node instanceof MethodNode;
	}

	private void run(ICodeNodeRef node) {
		if (node instanceof MethodNode) {
			this.pass.addTarget(((MethodNode) node).getMethodInfo().getRawFullId());
			this.context.getGuiContext().reloadActiveTab();
		} else {
			LOG.error("caret is not pointing at a method!");
		}
	}
}
