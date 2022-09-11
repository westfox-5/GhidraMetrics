package ghidrametrics.ui;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidrametrics.GhidraMetricsProvider;
import ghidrametrics.GhidraMetricsPlugin;
import resources.ResourceManager;

public class GhidraMetricsActionBack extends DockingAction {
	private final GhidraMetricsPlugin plugin;

	public GhidraMetricsActionBack(GhidraMetricsPlugin plugin) {
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
		
		provider.showView(null);
	}

}
