package jadx.plugins.decompiler;

import jadx.api.plugins.options.impl.BasePluginOptionsBuilder;

public class EvalMethodOptions extends BasePluginOptionsBuilder {

	private boolean enable = false;
	private String fridaProxyHost = "localhost";
	private int fridaProxyPort = 50051;

	@Override
	public void registerOptions() {
		boolOption(EvalMethod.PLUGIN_ID + ".enable")
				.description("enable plugin")
				.defaultValue(true)
				.setter(v -> enable = v);

		strOption(EvalMethod.PLUGIN_ID + ".fridaProxyHost")
				.description("Frida proxy host")
				.defaultValue("localhost")
				.setter(v -> fridaProxyHost = v);

		option(EvalMethod.PLUGIN_ID + ".fridaProxyPort", int.class)
				.description("Frida proxy port")
				.defaultValue(50051)
				.setter(v -> fridaProxyPort = v);
	}

	public boolean isEnable() {
		return enable;
	}

	public void setEnable(boolean enable) {
		this.enable = enable;
	}

	public String getFridaProxyHost() {
		return fridaProxyHost;
	}

	public int getFridaProxyPort() {
		return fridaProxyPort;
	}
}
