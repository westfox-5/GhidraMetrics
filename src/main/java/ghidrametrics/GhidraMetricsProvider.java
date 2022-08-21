package ghidrametrics;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.util.Set;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.util.Msg;
import ghidrametrics.base.BaseMetricProvider;
import ghidrametrics.base.ui.MetricButton;
import resources.Icons;

public class GhidraMetricsProvider extends ComponentProvider {
	
	private GhidraMetricsPlugin plugin;
	
	private JPanel panel;
	private DockingAction action;

	public GhidraMetricsProvider(GhidraMetricsPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		
		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		
		Set<BaseMetricProvider<?>> mProviders = plugin.getMetricProviders();
		JPanel innerPanel = new JPanel(new GridLayout(mProviders.size(), 1));
		
		mProviders.forEach( mProvider -> {
			innerPanel.add(new MetricButton(mProvider));
		});
		
		panel.add(new JScrollPane(innerPanel), BorderLayout.CENTER);
		setVisible(true);
	}

	// TODO: Customize actions
	private void createActions() {
		action = new DockingAction("My Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}