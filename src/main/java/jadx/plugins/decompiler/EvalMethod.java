package jadx.plugins.decompiler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.metadata.ICodeNodeRef;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.core.dex.nodes.MethodNode;

public class EvalMethod implements JadxPlugin {
	public static final String PLUGIN_ID = "jadx-eval-method";
	private static final Logger LOG = LoggerFactory.getLogger(EvalMethod.class);
	private final EvalMethodOptions options = new EvalMethodOptions();
	private EvalMethodPass pass;
	private JadxPluginContext context;

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

		FridaProxy fridaProxy;
		try {
			fridaProxy = new FridaProxy(options.getFridaProxyHost(), options.getFridaProxyPort());
		} catch (Exception e) {
			LOG.error("failed to create FridaProxy", e);
			return;
		}

		PackageUtils packageUtils = new PackageUtils(context, fridaProxy);

		pass = new EvalMethodPass(fridaProxy, packageUtils);

		LOG.info("adding plugin pass");
		context.addPass(pass);

		context.getGuiContext().addPopupMenuAction(
				"Evaluate calls to this method",
				(ICodeNodeRef node) -> options.isEnable() && node instanceof MethodNode,
				"G",
				(ICodeNodeRef node) -> run(node));

		LOG.info("plugin is ready");
		options.setEnable(true);
	}

	private void run(ICodeNodeRef node) {
		this.pass.addTarget(((MethodNode) node).getMethodInfo().getRawFullId());
		this.context.getGuiContext().reloadActiveTab();
	}
}
