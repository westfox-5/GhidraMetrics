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

import java.util.Set;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import it.unive.ghidra.metrics.base.GMetric;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = GhidraMetricsPlugin.PACKAGE_NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class GhidraMetricsPlugin extends ProgramPlugin {

	public static final String PACKAGE_NAME = "it.unive.ghidra.metrics";
	
	public static Set<Class<? extends GMetric>> getEnabledMetrics() {
		return Set.of(GMHalstead.class);
	}
	
	private final GMProvider provider;
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraMetricsPlugin(PluginTool tool) {
		super(tool, true, true);
		
		String pluginName = getName();
		provider = new GMProvider(this, pluginName);
		
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}
	
	public GMProvider getProvider() {
		return provider;
	}
}
