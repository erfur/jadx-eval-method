package jadx.plugins.decompiler;

import java.util.ArrayList;

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
	public FridaProxy fridaProxy = null;
	public String packageName;

	@Override
	public JadxPassInfo getInfo() {
		return new OrderedJadxPassInfo(
				"EvalMethodPass",
				"Evaluate methods in various ways and update the decompiler output.")
				.before("RegionMakerVisitor");
	}

	@Override
	public void init(RootNode root) {
		LOG.debug("Init pass");
	}

	@Override
	public boolean visit(ClassNode cls) {
		// return true if you want to visit the methods
		return true;
	}

	@Override
	public void visit(MethodNode mth) {
		LOG.info("visiting method {}", mth.getMethodInfo().getRawFullId());

		if (targetMethods.isEmpty()) {
			LOG.warn("target methods array is empty");
			return;
		} else if (mth.isNoCode()) {
			LOG.warn("method has no code");
			return;
		}

		mth.getBasicBlocks().forEach(block -> {
			block.getInstructions().forEach((InsnNode insn) -> {
				insn.getArguments().forEach((InsnArg arg) -> {
					if (arg.isInsnWrap()) {
						InsnNode argInsn = arg.unwrap();
						if (isInvokeTarget(argInsn, mth)) {
							String newStr = evalTarget((InvokeNode) argInsn);
							if (newStr != null) {
								insn.replaceArg(arg, InsnArg.wrapArg(new ConstStringNode(newStr)));
							}
						}
					}
				});
			});
		});
	}

	private String evalTarget(InvokeNode argInsn) {
		LOG.info("Evaluating method");
		var method = argInsn.getCallMth();
		var newValue = fridaProxy.evalMethod(
				packageName,
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
				LOG.info("Found call to {} in {}", callMth.getRawFullId(), mth.getMethodInfo().getRawFullId());
				return true;
			}
		}

		return false;
	}

	public void addTarget(String methodRawId) {
		LOG.error("Adding method to targets: {}", methodRawId);
		targetMethods.add(methodRawId);
	}
}
