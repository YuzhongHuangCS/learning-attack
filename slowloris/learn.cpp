#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>

using namespace std;
using namespace boost;
using namespace asio;

void createStream(deadline_timer* timer, const string& host, const string& path);
void appendStream(deadline_timer* timer, ip::tcp::iostream* stream);

int main(int argc, char *argv[]) {
	const int requests = 300;
	const int interval = 5;
	//const int times = 20;

	io_service io;
	deadline_timer** timers = new deadline_timer*[requests];

	for(int i = 0; i < requests; i++){
		timers[i] = new deadline_timer(io, posix_time::seconds(interval));
		createStream(timers[i], "localhost", "/");
	}

	io.run();
	return 0;
}

void createStream(deadline_timer* timer, const string& host, const string& path) {
	cout << "createStream" << endl;
	ip::tcp::iostream* stream = new ip::tcp::iostream(host, "http");

	(*stream) << format(
		"GET %1% HTTP/1.1\r\n"
		"Host: %2%\r\n"
		"User-Agent: Boost.Asio\r\n"
		"Accept: */*\r\n"
		"Connection: Keep-Alive\r\n"
	) % path % host;

	stream->flush();

	timer->async_wait(bind(appendStream, timer, stream));
}

void appendStream(deadline_timer* timer, ip::tcp::iostream* stream) {
	cout << "appendStream" << endl;
	(*stream) << "X-Via: Linux\r\n";
	stream->flush();

	timer->expires_from_now(posix_time::seconds(1));
	timer->async_wait(bind(appendStream, timer, stream));
}