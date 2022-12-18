/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.unive.ghidra.metrics;

import java.util.Collection;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import it.unive.ghidra.metrics.util.GMFactory;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = GhidraMetricsPlugin.PACKAGE_NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = GhidraMetricsPlugin.PLUGIN_NAME,
	description = GhidraMetricsPlugin.DESCR
)
//@formatter:on
public class GhidraMetricsPlugin extends ProgramPlugin {
	public static final String PACKAGE_NAME = "it.unive.ghidra.metrics";
	public static final String PLUGIN_NAME = "Ghidra Metrics";
	public static final String DESCR = "Ghidra Metrics Plugin";

	private final GhidraMetricsProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraMetricsPlugin(PluginTool tool) {
		super(tool);
		
		String pluginName = PLUGIN_NAME;
		provider = new GhidraMetricsProvider(this, pluginName);

		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		provider.locationChanged(loc);
	}

	public GhidraMetricsProvider getProvider() {
		return provider;
	}

	public Collection<String> getMetricNames() {
		return GMFactory.allMetricNames();
	}
}
