#include "slowloris-gui.h"

int main(int argc, char *argv[]) {
	RefPtr<Application> app = Application::create(argc, argv, "org.pillowsky.slowloris");
	
	SlowlorisWindow window;
	
	return app->run(*(window.create()));
}
