package jadx.plugins.example;

import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.HashMap;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.ICodeInfo;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;
import jadx.api.metadata.ICodeNodeRef;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.gui.JadxGuiContext;
import jadx.api.utils.CodeUtils;
import jadx.core.dex.instructions.ConstStringNode;
import jadx.core.dex.instructions.InvokeNode;
import jadx.core.dex.instructions.args.InsnArg;
import jadx.core.dex.instructions.args.InsnWrapArg;
import jadx.core.dex.instructions.args.RegisterArg;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.InsnNode;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.utils.files.FileUtils;
//import jadx.plugins.script.runtime.JadxScriptInstance;

public class EvalMethodWithFrida {
    private static final Logger LOG = LoggerFactory.getLogger(JavaMethod.class);

    JadxPluginContext context;
    // JadxScriptInstance script;
    JadxDecompiler decompiler;
    JadxGuiContext guiContext;

    HashMap<MethodNode, ArrayList<MethodNode>> methodRefs = new HashMap<MethodNode, ArrayList<MethodNode>>();

    EvalMethodWithFrida(JadxPluginContext context, JadxScriptInstance scriptInstance) {
        this.context = context;
        this.script = scriptInstance;
        this.decompiler = context.getDecompiler();
        this.guiContext = context.getGuiContext();
    }

    // fun getConstStr(arg: InsnArg): String? {
    // val insn = when (arg) {
    // is InsnWrapArg -> arg.wrapInsn
    // is RegisterArg -> arg.assignInsn
    // else -> null
    // }
    // if (insn is ConstStringNode) {
    // return insn.string
    // }
    // return null
    // }

    private String getConstStr(InsnArg arg) {
        InsnNode insn = null;
        if (arg instanceof InsnWrapArg) {
            insn = ((InsnWrapArg) arg).getWrapInsn();
        } else if (arg instanceof RegisterArg) {
            insn = ((RegisterArg) arg).getAssignInsn();
        }
        if (insn instanceof ConstStringNode) {
            return ((ConstStringNode) insn).getString();
        }
        return null;
    }

    public void run(ICodeNodeRef node) {
        MethodNode methodNode = (MethodNode) node;
        LOG.info("Decryption method found: " + methodNode.getName());

        JavaMethod javaMethod = methodNode.getJavaNode();

        List<File> files = this.context.getArgs().getInputFiles();

        files.forEach((file) -> {
            LOG.info("Input file: " + file.getAbsolutePath());
        });

        if (files.size() > 1) {
            LOG.info("Multiple files found, using the first one");
        }

        File file = files.get(0);
        LOG.info("Using file: " + file.getAbsolutePath());

        methodNode.getUseIn().forEach((useIn) -> {
            LOG.info("Used in: " + useIn.getName());
        });

        // extract the method call from the referenced method
        methodNode.getUseIn().forEach((useIn) -> {
            this.methodRefs.putIfAbsent(methodNode, new ArrayList<MethodNode>());
            this.methodRefs.get(methodNode).add(useIn);
        });

        this.methodRefs.forEach((method, refs) -> {
            LOG.info("Method: " + method);
            refs.forEach((ref) -> {
                LOG.info("Ref: " + ref);
                JavaClass cls = ref.getJavaNode().getTopParentClass();
                ICodeInfo code = cls.getCodeInfo();
                List<Integer> usePositions = cls.getUsePlacesFor(code, javaMethod);
                String codeStr = code.getCodeStr();

                usePositions.forEach((pos) -> {
                    LOG.info("Use position: " + pos);
                    String line = CodeUtils.getLineForPos(codeStr, pos);
                    LOG.info("Line: " + line);
                });
            });
        });

        LOG.info("Processing calls to the method...");
        this.script.getReplace().insns((mth, insn) -> {
            LOG.info("Method: " + mth.getName() + " Instruction: " + insn);
            if (insn instanceof InvokeNode
                    && ((InvokeNode) insn).getCallMth().getRawFullId() == methodNode.getMethodInfo().getRawFullId()) {
                LOG.info("Invoke: " + insn);
                String str = getConstStr(insn.getArg(0));
                if (str != null) {
                    LOG.info("String: " + str);
                    return new ConstStringNode(str);
                }
            }

            return null;
        });

        this.script.getDecompile().all();
    }

    @SuppressWarnings("unused")
    private void dead() {
        // ClassNode cls = methodNode.getTopParentClass();
        // LOG.info("Class: " + cls.getFullName());

        // ICodeInfo codeInfo = cls.getCode();
        // LOG.info("Code: " + codeInfo.getCodeStr());

        // // get the smali code of the whole class
        // String smali = cls.getJavaNode().getSmali();
        // LOG.info("Smali: " + smali);

        // // write to file
        // try {
        // Path path = Path.of("output.smali");
        // // write to file
        // FileUtils.writeFile(path, smali);
        // } catch (Exception e) {
        // LOG.error("Failed to write to file: " + e.getMessage());
        // }

        // String codeStr = methodNode.getParentClass().getJavaNode().getCode();
        // LOG.info("Code: " + codeStr);

        // methodNode.getCodeReader().visitInstructions((insnData) -> {
        // LOG.info("Instruction: " + insnData.toString());
        // });

        // TODO: extract the method and dependencies
        // TODO: execute the method with the given arguments
        // TODO: inline the result
    }
}
