package it.unive.ghidra.metrics.gui;

import docking.ActionContext;
import docking.action.MenuData;
import docking.menu.MultiActionDockingAction;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.GhidraMetricsProvider;
import it.unive.ghidra.metrics.base.GMAbstractMetricExporter;

public final class GMActionExport extends MultiActionDockingAction {

	private final GhidraMetricsPlugin plugin;

	private final GMAbstractMetricExporter.Type type;

	public GMActionExport(GhidraMetricsPlugin plugin, GMAbstractMetricExporter.Type type) {
		super("Export", plugin.getName());
		this.plugin = plugin;
		this.type = type;

		setMenuBarData(new MenuData(new String[] { type.name() }));
		setDescription("Export current metric as " + type.name());

		markHelpUnnecessary();
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext ctx) {
		GhidraMetricsProvider provider = plugin.getProvider();

		provider.doExport(type);
	}

}