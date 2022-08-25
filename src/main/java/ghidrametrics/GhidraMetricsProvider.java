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
import ghidrametrics.base.BaseMetricWrapper;
import ghidrametrics.base.ui.BaseMetricProvider;
import resources.Icons;

public class GhidraMetricsProvider extends ComponentProvider {
	
	private GhidraMetricsPlugin plugin;
	
	private BaseMetricProvider<?> activeProvider;
	private JComponent originalComponent, component;
	private DockingAction mainViewAction;

	public GhidraMetricsProvider(GhidraMetricsPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		
		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		component = new JPanel(new BorderLayout());
		
		Set<BaseMetricProvider<?>> mProviders = plugin.getMetricProviders();
		JPanel innerPanel = new JPanel(new GridLayout(mProviders.size(), 1));
		
		mProviders.forEach( mProvider -> {
			innerPanel.add(mProvider.getMetricButton(this));
		});
		
		component.add(new JScrollPane(innerPanel), BorderLayout.CENTER);
		this.originalComponent = component;
		setVisible(true);
	}

	private void createActions() {
		mainViewAction = new DockingAction("GO BACK", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showMainView();
			}
		};
		mainViewAction.setToolBarData(new ToolBarData(Icons.LEFT_ICON, null));
		mainViewAction.setEnabled(true);
		mainViewAction.markHelpUnnecessary();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}
	
	public BaseMetricProvider<?> getActiveProvider() {
		return activeProvider;
	}
	
	public <T extends BaseMetricWrapper> void showMetricView(BaseMetricProvider<T> provider) {
		this.activeProvider = provider;
		this.component = provider.getComponent();
		setSubTitle(provider.getName());
		dockingTool.addLocalAction(this, mainViewAction);
		refreshView();
	}
	public void showMainView() {
		this.activeProvider = null;
		this.component = this.originalComponent;
		setSubTitle(null);
		dockingTool.removeLocalAction(this, mainViewAction);
		refreshView();
	}
	
	private final void refreshView() {
		setVisible(false); setVisible(true);
	}
}