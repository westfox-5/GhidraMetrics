package ghidrametrics;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.swing.JComponent;

import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.util.Msg;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidrametrics.base.BaseMetricProvider;
import ghidrametrics.base.BaseMetricWrapper;
import ghidrametrics.ui.GhidraMetricsActionBack;
import ghidrametrics.ui.GhidraMetricsActionExport;
import ghidrametrics.ui.GhidraMetricsWindowManager;
import ghidrametrics.util.StringUtils;

public class GhidraMetricsMainProvider extends ComponentProvider {
	
	private GhidraMetricsPlugin plugin;
	
	private final GhidraMetricsWindowManager wManager;
	private BaseMetricProvider<?> activeProvider;
	private List<DockingAction> actions;

	public GhidraMetricsMainProvider(GhidraMetricsPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		
		this.wManager = new GhidraMetricsWindowManager(plugin);
		
		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		Set<BaseMetricProvider<?>> enabledProviders = plugin.getEnabledMetricProviders();
		wManager.addMetricProviders(enabledProviders);
		
		setVisible(true);
	}

	private void createActions() {
		this.actions = new ArrayList<>();
		
		actions.add(new GhidraMetricsActionBack(plugin));
		
		for (GhidraMetricsExporter.Type type: GhidraMetricsExporter.Type.values()) {
			actions.add(new GhidraMetricsActionExport(plugin, type));
		}
	}

	@Override
	public JComponent getComponent() {
		return wManager.getComponent();
	}
	
	public BaseMetricProvider<?> getActiveProvider() {
		return activeProvider;
	}
	
	public void showView(BaseMetricProvider<? extends BaseMetricWrapper> provider) {
		this.activeProvider = provider;
		
		if (activeProvider!=null) activeProvider.init();
		
		wManager.showView(activeProvider);
		refreshView();
	}
	
	public void doExport(GhidraMetricsExporter.Type type) {
		if (activeProvider == null) 
			throw new RuntimeException("ERROR: No active provider is selected!");

		// TODO lock UI while export in process?
		BaseMetricWrapper wrapper = activeProvider.getWrapper();
		Path export = GhidraMetricsExporter.of(type).export(wrapper);
		
		GhidraFileChooser fileChooser = new GhidraFileChooser(getComponent());
		fileChooser.setMultiSelectionEnabled(false);
		fileChooser.setSelectedFileFilter(new GhidraFileFilter() {
			@Override
			public String getDescription() {
				return "Only " + type.name() + " files";
			}
			
			@Override
			public boolean accept(File arg0, GhidraFileChooserModel arg1) {					
				String extension = StringUtils.getFileExtension(arg0);
				return type.getExtension().equalsIgnoreCase(extension);
			}
		});
		
		File selectedFile = fileChooser.getSelectedFile();
		
		try {
			Path path = selectedFile.toPath();
			Files.copy(export, path, StandardCopyOption.COPY_ATTRIBUTES, StandardCopyOption.REPLACE_EXISTING);
			Files.deleteIfExists(export);
			
			Msg.info(this, "Export to file: "+ path.toAbsolutePath());
			
		// TODO handle these exceptions more gracefully
		} catch (IOException x) {
			x.printStackTrace();
		}
	}
	
	public final void refreshView() {
		if (activeProvider == null) {
			// main view
			setSubTitle(null);
			removeLocalActions();
			
		} else {
			// metric view
			setSubTitle(activeProvider.getWrapper().getName());
			addLocalActions();
		}

		wManager.refresh();
	}
	
	private final void addLocalActions() {
		for (DockingAction action: actions) {
			dockingTool.addLocalAction(this, action);
		}
	}
	
	private final void removeLocalActions() {
		for (DockingAction action: actions) {
			dockingTool.removeLocalAction(this, action);
		}
	}
}