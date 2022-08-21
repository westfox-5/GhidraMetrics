package ghidrametrics.base.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;

import ghidrametrics.base.BaseMetricProvider;

public class MetricButton extends JButton implements ActionListener {
	
	private BaseMetricProvider<?> mProvider;
	
	public MetricButton(BaseMetricProvider<?> mProvider) {
		super(mProvider.getMetricName());
		this.mProvider = mProvider;
		
		setActionCommand(mProvider.getMetricName());
		addActionListener(this);
	}
	
	@Override
	public void actionPerformed(ActionEvent ae) {
		String actionCommand = ae.getActionCommand();
		if (actionCommand.equals(mProvider.getMetricName())) {
			mProvider.init();
			mProvider.setVisible(true);
		}
	}

}
