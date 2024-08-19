package jadx.plugins.decompiler;

import jadx.api.plugins.options.impl.BasePluginOptionsBuilder;

public class EvalMethodOptions extends BasePluginOptionsBuilder {

	private boolean enable = true;
	private String scriptPath = "";

	@Override
	public void registerOptions() {
		boolOption(EvalMethod.PLUGIN_ID + ".enable")
				.description("enable plugin")
				.defaultValue(true)
				.setter(v -> enable = v);

		strOption(EvalMethod.PLUGIN_ID + ".script")
				.description("Frida script path")
				.defaultValue("")
				.setter(v -> scriptPath = v);
	}

	public boolean isEnable() {
		return enable;
	}

	public String getScriptPath() {
		return scriptPath;
	}
}
