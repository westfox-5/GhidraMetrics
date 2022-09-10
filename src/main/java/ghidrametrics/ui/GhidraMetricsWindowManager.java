package ghidrametrics.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.Collection;

import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;

import ghidrametrics.GhidraMetricsPlugin;
import ghidrametrics.base.BaseMetricProvider;

public class GhidraMetricsWindowManager {
	
	private final GhidraMetricsPlugin plugin;
	
	private final JPanel 
			mainComponent,	// Main Wrapper
			pnlMetricList, 	// Metrics buttons list
			pnlMetricMain  	// Metric wrapper
	;
	
	private final JLabel 
		lblMetricName
	;
	
	/**
	 * Create the frame.
	 */
	public GhidraMetricsWindowManager(GhidraMetricsPlugin plugin) {
		this.plugin = plugin;
		
		mainComponent = new JPanel();
		mainComponent.setBorder(new EmptyBorder(5, 5, 5, 5));

		mainComponent.setLayout(new BorderLayout(0, 0));
		
		pnlMetricMain = new JPanel();
		pnlMetricMain.setVisible(false);
		pnlMetricMain.setMaximumSize(new Dimension(32767, 30));
		mainComponent.add(pnlMetricMain, BorderLayout.NORTH);
		pnlMetricMain.setLayout(new BorderLayout(0, 0));
		
		JPanel pnlMetricHeader = new JPanel();
		pnlMetricMain.add(pnlMetricHeader, BorderLayout.NORTH);
		pnlMetricHeader.setMaximumSize(new Dimension(32767, 30));
		pnlMetricHeader.setLayout(new BoxLayout(pnlMetricHeader, BoxLayout.X_AXIS));
		
		JPanel pnlMetricFooter= new JPanel();
		pnlMetricMain.add(pnlMetricFooter, BorderLayout.SOUTH);
		
		lblMetricName = new JLabel();
		pnlMetricHeader.add(lblMetricName);
		lblMetricName.setHorizontalAlignment(SwingConstants.LEFT);
		
		pnlMetricList = new JPanel();
		mainComponent.add(pnlMetricList, BorderLayout.CENTER);
		pnlMetricList.setLayout(new GridLayout(0, 1, 0, 0));
		pnlMetricList.setVisible(true);
	}

	public JPanel getComponent() {
		return mainComponent;
	}

	public final void addMetricProviders(Collection<BaseMetricProvider<?>> mProviders) {
		for (BaseMetricProvider<?> mProvider: mProviders) {
			pnlMetricList.add(GhidraMetricsWrapperButton.of(plugin, mProvider));
		}
	}
	
	public final void showView(BaseMetricProvider<?> mProvider) {
		if (mProvider == null) {
			pnlMetricMain.setVisible(false);
			pnlMetricList.setVisible(true);

		} else {
			lblMetricName.setText(mProvider.getWrapper().getName());
			
			JComponent component = mProvider.getComponent();
			pnlMetricMain.add(component, BorderLayout.CENTER); 

			pnlMetricList.setVisible(false);
			pnlMetricMain.setVisible(true);			
		}
		
		mainComponent.revalidate(); // note: goes recursively on children!
	}

	public final void refresh() {
		mainComponent.repaint();
	}
}
