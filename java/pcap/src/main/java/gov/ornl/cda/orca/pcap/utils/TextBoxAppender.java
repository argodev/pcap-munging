/**
 * 
 */
package gov.ornl.cda.orca.pcap.utils;

import org.apache.log4j.WriterAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Text;

/**
 * @author argodev
 *
 */
public class TextBoxAppender extends WriterAppender {
	
	private static Text loggingTextBox = null;

	/** set the target Text control into which the logging information should appear */
	public void setTextBox(Text loggingTextBox) {
		TextBoxAppender.loggingTextBox = loggingTextBox;
	}
	
	public void append(LoggingEvent loggingEvent) {
		final String message = this.layout.format(loggingEvent);
		
		Display display = loggingTextBox.getDisplay();
		display.asyncExec(new Runnable() {
            public void run() {
            	loggingTextBox.append(message);
            }
        });
	}
}


