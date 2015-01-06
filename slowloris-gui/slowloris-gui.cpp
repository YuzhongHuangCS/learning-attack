#include <iostream>
#include <boost/format.hpp>
#include "slowloris-gui.h"

Window* SlowlorisWindow::create() {
	/* Load the Glade file and instiate its widgets */
	Glib::RefPtr<Builder> builder;
	try {
		builder = Builder::create_from_file(ui_file);
	}
	catch (const Glib::FileError & ex) {
		cerr << ex.what() << endl;
		abort();
	}

	ui_signal_connect(builder);

	return mainWindow;
}

/* Connect signals */
void SlowlorisWindow::ui_signal_connect(Glib::RefPtr<Builder> &builder) {
	builder->get_widget("main_window", mainWindow);
	builder->get_widget("dest", destEntry);
	builder->get_widget("port", portEntry);
	builder->get_widget("location", locationEntry);
	builder->get_widget("concurrency", concurrencyEntry);
	builder->get_widget("threads", threadsEntry);
	builder->get_widget("speed", speedEntry);
	builder->get_widget("blocks", blocksEntry);
	builder->get_widget("interval", intervalEntry);
	builder->get_widget("expires", expiresEntry);
	builder->get_widget("debug", debugCheck);
	builder->get_widget("attacking", attackSpinner);
	builder->get_widget("attack", attackButton);

	attackButton->signal_clicked().connect(sigc::mem_fun(*this, &SlowlorisWindow::on_attackButton_clicked));
}

/* Signal handler */
void SlowlorisWindow::on_attackButton_clicked() {
	Options option = getOptions();

	MessageDialog dialog(*mainWindow, (format("Slowloris attack against %1% launching") % option["dest"]).str());
	dialog.set_secondary_text((format("Logs will be saved to %1%.txt") % option["dest"]).str());
	dialog.run();

	Threads::Thread::create(sigc::bind(sigc::ptr_fun(launchSlowloris), option));
	attackButton->hide();
	attackSpinner->show();
	mainWindow->set_title("Slowloris - attacking");
}

/* internal function */
Options SlowlorisWindow::getOptions() {
	Options option;
	option["dest"] = destEntry->get_text();
	option["port"] = portEntry->get_text();
	option["location"] = locationEntry->get_text();
	option["concurrency"] = concurrencyEntry->get_text();
	option["threads"] = threadsEntry->get_text();
	option["speed"] = speedEntry->get_text();
	option["blocks"] = blocksEntry->get_text();
	option["interval"] = intervalEntry->get_text();
	option["expires"] = expiresEntry->get_text();
	option["debug"] = to_string(debugCheck->get_active());

	return option;
} 