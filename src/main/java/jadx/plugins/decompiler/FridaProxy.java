package jadx.plugins.decompiler;

import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.grpc.ManagedChannelBuilder;
import jadx.api.JavaMethod;
import jadx.plugins.decompiler.FridaEvalProxyGrpc.FridaEvalProxyBlockingStub;
import jadx.plugins.decompiler.Rpc.EvalReply;
import jadx.plugins.decompiler.Rpc.EvalRequest;
import jadx.plugins.decompiler.Rpc.EvalStatus;
import jadx.plugins.decompiler.Rpc.InstallReply;
import jadx.plugins.decompiler.Rpc.InstallRequest;
import jadx.plugins.decompiler.Rpc.InstallStatus;

public class FridaProxy {
    private static final Logger LOG = LoggerFactory.getLogger(JavaMethod.class);
    private final FridaEvalProxyBlockingStub stub;

    public FridaProxy(String host, int port) {
        this(ManagedChannelBuilder.forAddress(host, port).usePlaintext());
    }

    public FridaProxy(ManagedChannelBuilder<?> channelBuilder) {
        LOG.info("Creating FridaProxy");
        this.stub = FridaEvalProxyGrpc.newBlockingStub(channelBuilder.build());
    }

    public void installPackage(String packageName) {
        InstallRequest request = InstallRequest.newBuilder().setPackagePath(packageName).build();
        InstallReply reply = stub.install(request);

        if (reply.getStatus().equals(InstallStatus.INSTALL_OK)) {
            LOG.info("Successfully installed package: " + packageName);
        } else if (reply.getStatus().equals(InstallStatus.INSTALL_ALREADY_INSTALLED)) {
            LOG.info("Package already installed: " + packageName);
        } else if (reply.getStatus().equals(InstallStatus.INSTALL_ERR_NO_DEVICES)) {
            LOG.error("Failed to install: No devices found");
            throw new RuntimeException("Failed to install: No devices found");
        } else {
            LOG.error("Failed to install package: " + packageName);
            LOG.error("Error message: " + reply.getError());
            throw new RuntimeException("Failed to install package: " + packageName);
        }
    }

    public String evalMethod(String packageName, String className, String methodName, String methodSignature,
            ArrayList<String> methodArgs) {
        var builder = EvalRequest.newBuilder()
                .setPackageName(packageName)
                .setClassName(className)
                .setMethodName(methodName)
                .setMethodSignature(methodSignature);

        LOG.info("Arg count: " + methodArgs.size());

        for (String arg : methodArgs) {
            builder.addMethodArgs(hexlify(arg));
        }

        EvalRequest request = builder.build();
        EvalReply reply = stub.eval(request);

        if (reply.getStatus().equals(EvalStatus.EVAL_OK)) {
            LOG.info("Successfully evaluated method: " + methodName);
            return reply.getResult();
        } else {
            LOG.error("Failed to evaluate method: " + methodName);
            LOG.error("Error message: " + reply.getError());
            return null;
        }
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
}
