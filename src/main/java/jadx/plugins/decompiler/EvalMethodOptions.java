package jadx.plugins.decompiler;

import jadx.api.plugins.options.impl.BasePluginOptionsBuilder;

public class EvalMethodOptions extends BasePluginOptionsBuilder {

	private boolean enable = false;

	@Override
	public void registerOptions() {
		boolOption(EvalMethod.PLUGIN_ID + ".enable")
				.description("enable plugin")
				.defaultValue(true)
				.setter(v -> enable = v);
	}

	public boolean isEnable() {
		return enable;
	}

	public void setEnable(boolean enable) {
		this.enable = enable;
	}
}
