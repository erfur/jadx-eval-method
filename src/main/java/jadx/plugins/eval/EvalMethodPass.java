package jadx.plugins.eval;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;

public class EvalMethodPass implements JadxDecompilePass {
	private static final Logger LOG = LoggerFactory.getLogger(JavaMethod.class);

	private final ArrayList<String> targetMethods = new ArrayList<String>();

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
							LOG.info("Replacing arg");
							// TODO create an executor to request the value from the frida eval server
							var replacedValue = new ConstStringNode("replaced");
							insn.replaceArg(arg, InsnArg.wrapArg(replacedValue));
						}
					}
				});
			});
		});
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
