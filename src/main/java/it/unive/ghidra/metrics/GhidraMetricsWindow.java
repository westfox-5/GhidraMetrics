package it.unive.ghidra.metrics;

import java.awt.BorderLayout;
import java.awt.GridLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import ghidra.util.Swing;
import it.unive.ghidra.metrics.base.GMBaseWindow;
import it.unive.ghidra.metrics.base.interfaces.GMMetricControllerGUI;
import it.unive.ghidra.metrics.gui.GMMetricButton;
import it.unive.ghidra.metrics.impl.GhidraMetricsFactory;

public class GhidraMetricsWindow extends GMBaseWindow {

	private JPanel pnlMainContainer;
	private JPanel pnlMetricContainer;

	public GhidraMetricsWindow(GhidraMetricsPlugin plugin) {
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
		int numMetrics = GhidraMetricsFactory.allMetrics().size();
		pnlMainContainer.setLayout(new GridLayout(numMetrics, 1, 10, 10));

		return component;
	}

	public final void updateWindow(GMMetricControllerGUI manager) {
		pnlMetricContainer.removeAll();
		
		if (manager == null) {
			
			getComponent().remove(pnlMetricContainer);
			getComponent().add(pnlMainContainer);

		} else {
			JComponent component = manager.getWindow().getComponent();
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
		GhidraMetricsFactory.allMetrics().forEach(metricName -> {
			pnlMainContainer.add(new GMMetricButton(getPlugin(), metricName));
		});
	}
}
