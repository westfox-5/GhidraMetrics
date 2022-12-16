package it.unive.ghidra.metrics.gui;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.GhidraMetricsProvider;
import resources.ResourceManager;

public class GMActionBack extends DockingAction {
	private final GhidraMetricsPlugin plugin;

	public GMActionBack(GhidraMetricsPlugin plugin) {
		super("Back", plugin.getName());
		this.plugin = plugin;

		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/left.png"), null));
		setDescription("Go back to main view");

		markHelpUnnecessary();
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext arg0) {
		GhidraMetricsProvider provider = plugin.getProvider();

		provider.showMainWindow();
	}

}
