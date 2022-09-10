package ghidrametrics.ui;

import docking.ActionContext;
import docking.action.MenuData;
import docking.menu.MultiActionDockingAction;
import ghidrametrics.GhidraMetricsExporter;
import ghidrametrics.GhidraMetricsMainProvider;
import ghidrametrics.GhidraMetricsPlugin;

public final class GhidraMetricsActionExport extends MultiActionDockingAction {
	
	private final GhidraMetricsPlugin plugin;
	
	private final GhidraMetricsExporter.Type type;
	
	public GhidraMetricsActionExport(GhidraMetricsPlugin plugin, GhidraMetricsExporter.Type type) {
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
		GhidraMetricsMainProvider provider = plugin.getProvider();
		
		provider.doExport(type);
	}

}