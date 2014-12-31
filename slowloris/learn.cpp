#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>

using namespace std;
using namespace boost;
using namespace asio;


class Memory {

public:
	Memory(deadline_timer* t, ip::tcp::iostream* s, int i) :
		timer(t),
		stream(s),
		index(i)
	{
	}

	deadline_timer* timer;
	ip::tcp::iostream* stream;
	int index;
};

void createStream(deadline_timer* timer, const string& host, const string& path);
void appendStream(Memory* mem);


int main(int argc, char *argv[]) {
	const int requests = 10;
	const int interval = 1;

	io_service io;
	deadline_timer** timers = new deadline_timer*[requests];

	for(int i = 0; i < requests; i++){
		timers[i] = new deadline_timer(io, posix_time::seconds(interval));
		createStream(timers[i], "blog.pillowsky.org", "/");
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

	timer->async_wait(bind(appendStream, new Memory(timer, stream, 0)));
}

void appendStream(Memory* mem) {
	cout << mem->index << endl;
	*(mem->stream) << format("X-Trunk: %1%\r\n") % mem->index++;
	
	mem->stream->flush();
	mem->timer->expires_from_now(posix_time::seconds(1));
	mem->timer->async_wait(bind(appendStream, mem));
}