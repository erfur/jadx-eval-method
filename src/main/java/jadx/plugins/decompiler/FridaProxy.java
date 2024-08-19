package jadx.plugins.decompiler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.JavaMethod;

import java.io.File;
import java.util.ArrayList;

public class FridaProxy {
    private static final Logger LOG = LoggerFactory.getLogger(JavaMethod.class);

    String scriptPath;

    public FridaProxy(String scriptPath) {
        LOG.info("creating frida client with script: %s".formatted(scriptPath));
        this.scriptPath = scriptPath;
    }

    public void installPackage(String packagePath) {
        LOG.info("installing package: {}", packagePath);
        String out = runFridaCommand(new ArrayList<String>() {
            {
                add("install");
                add(packagePath);
            }
        });
        LOG.info("install output: {}", out);
    }

    public String evalMethod(String packageName, String className, String methodName, String methodSignature,
            ArrayList<String> methodArgs) {
        LOG.info("evaluating method");

        String hex = hexlify(methodArgs.get(0));

        // ArrayList<String> cmdArgs = new ArrayList<>();
        // cmdArgs.add("eval");
        // cmdArgs.add(packageName);
        // cmdArgs.add(methodName);
        // cmdArgs.addAll(args);

        return runFridaCommand(new ArrayList<String>() {
            {
                add("eval");
                add(packageName);
                add(className);
                add(methodName);
                add(hex);
            }
        });
    }

    private String hexlify(String string) {
        StringBuilder sb = new StringBuilder();
        try {
            for (byte c : string.getBytes("UTF-8")) {
                sb.append(String.format("%02x", c));
            }
        } catch (Exception e) {
            LOG.error("error hexlifying string", e);
        }
        return sb.toString();
    }

    private String runFridaCommand(ArrayList<String> args) {
        args.add(0, "python");
        args.add(1, scriptPath);

        return runCommand(args, new File(scriptPath).getParent());
    }

    private String runCommand(ArrayList<String> args, String cwd) {
        String out = "";
        String err = "";
        LOG.info("running command: {}", args);
        ProcessBuilder pb = new ProcessBuilder(args).directory(new File(cwd));
        try {
            Process p = pb.start();
            p.waitFor();
            out = new String(p.getInputStream().readAllBytes()).strip();
            err = new String(p.getErrorStream().readAllBytes()).strip();
            LOG.error("command output: '{}'", out);
            LOG.error("stderr: '{}'", err);
        } catch (Exception e) {
            LOG.error("error running command", e);
        }

        return out;
    }
}
