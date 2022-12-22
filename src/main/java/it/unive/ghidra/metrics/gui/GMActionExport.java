package it.unive.ghidra.metrics.gui;

import docking.ActionContext;
import docking.action.MenuData;
import docking.menu.MultiActionDockingAction;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.GhidraMetricsProvider;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;

public final class GMActionExport extends MultiActionDockingAction {
	private final GhidraMetricsPlugin plugin;
	private final GMMetricExporter.FileFormat fileFormat;

	public GMActionExport(GhidraMetricsPlugin plugin, GMMetricExporter.FileFormat fileFormat) {
		super("Export", plugin.getName());
		this.plugin = plugin;
		this.fileFormat = fileFormat;

		setMenuBarData(new MenuData(new String[] { fileFormat.name() }));
		setDescription("Export current metric as " + fileFormat.name());

		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext ctx) {
		GhidraMetricsProvider provider = plugin.getProvider();

		provider.doExport(fileFormat);
	}

}