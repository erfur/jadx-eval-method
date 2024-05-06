package jadx.plugins.eval;

import jadx.api.metadata.ICodeNodeRef;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.core.dex.nodes.MethodNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EvalMethod implements JadxPlugin {
	public static final String PLUGIN_ID = "eval-method";
	private static final Logger LOG = LoggerFactory.getLogger(EvalMethod.class);

	private final EvalMethodOptions options = new EvalMethodOptions();

	private final EvalMethodPass pass = new EvalMethodPass();
	private JadxPluginContext context;

	@Override
	public JadxPluginInfo getPluginInfo() {
		return new JadxPluginInfo(PLUGIN_ID, "Eval Method",
				"Evaluate methods in various ways and update the decompiler output.");
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

		LOG.info("adding plugin pass");
		context.addPass(pass);

		context.getGuiContext().addPopupMenuAction(
				"Add method to eval targets",
				(ICodeNodeRef node) -> enabled(node),
				"G",
				(ICodeNodeRef node) -> run(node));
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
