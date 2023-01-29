package it.unive.ghidra.metrics;

import java.awt.BorderLayout;
import java.awt.GridLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import ghidra.util.Swing;
import it.unive.ghidra.metrics.base.GMBaseWindowManager;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerGUI;
import it.unive.ghidra.metrics.gui.GMMetricButton;

public class GhidraMetricsWindowManager extends GMBaseWindowManager {

	private JPanel pnlMainContainer;
	private JPanel pnlMetricContainer;

	public GhidraMetricsWindowManager(GhidraMetricsPlugin plugin) {
		super(plugin);
	}

	@Override
	public boolean init() {
		createAllMetricButtons();
		
		return true;
	}

	@Override
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setBorder(new EmptyBorder(5, 5, 5, 5));
		component.setLayout(new BorderLayout(0, 0));

		pnlMetricContainer = new JPanel();
		pnlMetricContainer.setLayout(new BorderLayout(0, 0));

		pnlMainContainer = new JPanel();
		int numMetrics = getPlugin().getMetricNames().size();
		pnlMainContainer.setLayout(new GridLayout(numMetrics, 1, 10, 10));

		return component;
	}

	public final void updateWindow(GMMetricManagerGUI manager) {
		pnlMetricContainer.removeAll();
		
		if (manager == null) {
			
			getComponent().remove(pnlMetricContainer);
			getComponent().add(pnlMainContainer);

		} else {
			JComponent component = manager.getWindowManager().getComponent();
			pnlMetricContainer.add(component, BorderLayout.CENTER);
			
			pnlMetricContainer.revalidate();
			pnlMetricContainer.repaint();

			getComponent().remove(pnlMainContainer);
			getComponent().add(pnlMetricContainer);
			
		}
		Swing.runNow( () -> { 
			getComponent().revalidate();
			getComponent().repaint();
			getComponent().grabFocus();
		});
	}

	private final void createAllMetricButtons() {
		getPlugin().getMetricNames().forEach(metricName -> {
			pnlMainContainer.add(new GMMetricButton(getPlugin(), metricName));
		});
	}
}
