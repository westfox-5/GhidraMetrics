package it.unive.ghidra.metrics.gui;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.GhidraMetricsProvider;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;

public final class GMActionExport extends DockingAction {
	private final GhidraMetricsPlugin plugin;
	private final GMMetricExporter.FileFormat fileFormat;

	public GMActionExport(GhidraMetricsPlugin plugin, String metricName, GMMetricExporter.FileFormat fileFormat) {
		super("Export as " + fileFormat.name(), plugin.getName());
		this.plugin = plugin;
		this.fileFormat = fileFormat;

		setMenuBarData(new MenuData(new String[] { "Export as " + fileFormat.name() }, metricName));
		setDescription("Export current metric as " + fileFormat.name());
		setEnabled(true);
		setSupportsDefaultToolContext(true);
		setAddToAllWindows(true);
	}

	@Override
	public void actionPerformed(ActionContext ctx) {
		GhidraMetricsProvider provider = plugin.getProvider();

		provider.doExport(fileFormat);
	}

}