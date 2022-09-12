package it.unive.ghidra.metrics.ui;

import docking.ActionContext;
import docking.action.MenuData;
import docking.menu.MultiActionDockingAction;
import it.unive.ghidra.metrics.GMExporter;
import it.unive.ghidra.metrics.GMProvider;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public final class GMActionExport extends MultiActionDockingAction {
	
	private final GhidraMetricsPlugin plugin;
	
	private final GMExporter.Type type;
	
	public GMActionExport(GhidraMetricsPlugin plugin, GMExporter.Type type) {
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
		GMProvider provider = plugin.getProvider();
		
		provider.doExport(type);
	}

}