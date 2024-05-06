package jadx.plugins.eval;

import jadx.api.plugins.options.impl.BasePluginOptionsBuilder;

public class EvalMethodOptions extends BasePluginOptionsBuilder {

	private boolean enable = true;

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
}
