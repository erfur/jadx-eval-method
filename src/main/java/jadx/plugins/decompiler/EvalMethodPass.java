package jadx.plugins.decompiler;

import java.util.ArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.JavaMethod;
import jadx.api.plugins.pass.JadxPassInfo;
import jadx.api.plugins.pass.impl.OrderedJadxPassInfo;
import jadx.api.plugins.pass.types.JadxDecompilePass;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.instructions.ConstStringNode;
import jadx.core.dex.instructions.InvokeNode;
import jadx.core.dex.instructions.args.InsnArg;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.InsnNode;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.dex.nodes.RootNode;

public class EvalMethodPass implements JadxDecompilePass {
	private static final Logger LOG = LoggerFactory.getLogger(JavaMethod.class);

	private final ArrayList<String> targetMethods = new ArrayList<String>();
	private final FridaProxy fridaProxy;
	private final PackageUtils packageUtils;

	EvalMethodPass(FridaProxy fridaProxy, PackageUtils packageUtils) {
		this.fridaProxy = fridaProxy;
		this.packageUtils = packageUtils;
	}

	@Override
	public JadxPassInfo getInfo() {
		return new OrderedJadxPassInfo(
				"EvalMethodPass",
				"Evaluate methods in various ways and update the decompiler output.")
				.before("RegionMakerVisitor");
	}

	@Override
	public void init(RootNode root) {
		LOG.info("EvalMethodPass init");
	}

	@Override
	public boolean visit(ClassNode cls) {
		if (!packageUtils.isAppInstalled()) {
			LOG.error("App not installed, cannot evaluate methods");
			return false;
		} else if (packageUtils.getPackageName() == null) {
			LOG.error("Failed to get package name, cannot evaluate methods");
			return false;
		}

		// return true to visit methods
		return true;
	}

	@Override
	public void visit(MethodNode mth) {
		LOG.trace("visiting method {}", mth.getMethodInfo().getRawFullId());

		if (targetMethods.isEmpty()) {
			return;
		} else if (mth.isNoCode()) {
			return;
		}

		mth.getBasicBlocks().forEach(block -> {
			block.getInstructions().forEach((InsnNode insn) -> {
				LOG.trace("Processing instruction: {}", insn);
				insn.getArguments().forEach((InsnArg arg) -> {
					LOG.trace("Processing argument: {}", arg);
					if (arg.isInsnWrap()) {
						InsnNode argInsn = arg.unwrap();
						if (isInvokeTarget(argInsn, mth)) {
							String newStr = evalTarget((InvokeNode) argInsn);
							if (newStr != null) {
								LOG.info("Replacing {} with '{}'", arg, newStr);
								// TODO: cache replacements
								insn.replaceArg(arg, InsnArg.wrapArg(new ConstStringNode(newStr)));
							}
						}
					} else {
						LOG.trace("Argument is not an instruction: {}", arg);
					}
				});

				if (insn instanceof InvokeNode) {
					InvokeNode invokeInsn = (InvokeNode) insn;
					if (isInvokeTarget(invokeInsn, mth)) {
						String newStr = evalTarget(invokeInsn);
						if (newStr != null) {
							LOG.info("Replacing {} with '{}'", invokeInsn, newStr);
							block.getInstructions().set(block.getInstructions().indexOf(invokeInsn),
									new ConstStringNode(newStr));
						}
					}
				}
			});
		});
	}

	private String evalTarget(InvokeNode argInsn) {
		LOG.info("Evaluating method");
		var method = argInsn.getCallMth();
		var newValue = fridaProxy.evalMethod(
				packageUtils.getPackageName(),
				method.getDeclClass().getRawName(),
				method.getName(),
				method.getShortId(),
				new ArrayList<String>() {
					{
						for (InsnArg arg : argInsn.getArguments()) {
							add(((ConstStringNode) arg.unwrap()).getString());
						}
					}
				});

		if (newValue == null) {
			LOG.error("Failed to evaluate method");
			return null;
		}

		return newValue;
	}

	private boolean isInvokeTarget(InsnNode insn, MethodNode mth) {
		if (insn instanceof InvokeNode) {
			LOG.trace("Processing invoke insn {}", insn);
			MethodInfo callMth = ((InvokeNode) insn).getCallMth();
			LOG.trace("Processing call to {}", callMth.getRawFullId());
			if (targetMethods.contains(callMth.getRawFullId())) {
				LOG.debug("Found call to {} in {}", callMth.getRawFullId(), mth.getMethodInfo().getRawFullId());
				return true;
			}
		} else {
			LOG.trace("Not an invoke insn: {}", insn);
		}

		return false;
	}

	public void addTarget(String methodRawId) {
		LOG.info("Adding method to targets: {}", methodRawId);
		targetMethods.add(methodRawId);
	}
}
