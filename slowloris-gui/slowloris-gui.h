#ifndef _SLOWLORIS_WINDOW_H_
#define _SLOWLORIS_WINDOW_H_

#include <gtkmm.h>
#include "slowloris.h"

using namespace std;
using namespace Glib;
using namespace Gtk;

static string ui_file = "slowloris.ui";

class SlowlorisWindow {
public:
	Window* create();

private:
	//Signal handlers
	void on_attackButton_clicked();

	//Widget pointer in the UI file
	Window* mainWindow = NULL;
	Entry* destEntry = NULL;
	Entry* portEntry = NULL;
	Entry* locationEntry = NULL;
	Entry* concurrencyEntry = NULL;
	Entry* threadsEntry = NULL;
	Entry* speedEntry = NULL;
	Entry* blocksEntry = NULL;
	Entry* intervalEntry = NULL;
	Entry* expiresEntry = NULL;
	CheckButton* debugCheck = NULL;
	Spinner* attackSpinner = NULL;
	Button* attackButton = NULL;

	//Signal Connecters
	void ui_signal_connect(Glib::RefPtr<Gtk::Builder>& builder);

	//Internal functions
	Options getOptions();
};

#endif // _SLOWLORIS_WINDOW_H_
