#include <iostream>
#include <list>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>

using namespace std;
using namespace boost;
using namespace asio;

int concurrency = 240;
int maxTrunk = 60;
int interval = 5;
string host = "localhost";
string path = "/";

class Request {
public:
	deadline_timer* timer;
	ip::tcp::iostream* stream;
	int id;
	int count;

	Request(io_service& io, int id) : id(id), count(0) {
		timer = new deadline_timer(io, posix_time::seconds(interval));
		stream = new ip::tcp::iostream(host, "http");
	}
	~Request() {
		delete timer;
		delete stream;
	}

	void open() {
		cout << format("Open Request: %1%") % id << endl;

		*stream << format("GET %1% HTTP/1.1\r\n"
				  "Host: %2%\r\n"
				  "User-Agent: Boost.Asio\r\n"
				  "Accept: */*\r\n"
				  "Connection: Keep-Alive\r\n") % path % host;

		stream->flush();
		timer->expires_from_now(posix_time::seconds(interval));
		timer->async_wait(bind(&Request::append, this));
	}

	void append() {
		cout << format("Append Request: %1%->%2%") % id % count << endl;
		*stream << format("X-Trunk: %1%\r\n") % count;
		stream->flush();

		if (count < maxTrunk) {
			count++;
			timer->expires_from_now(posix_time::seconds(interval));
			timer->async_wait(bind(&Request::append, this));
		} else {
			timer->expires_from_now(posix_time::seconds(interval));
			timer->async_wait(bind(&Request::close, this));
		}
	}

	void close() {
		*stream << "\r\n";
		stream->flush();
		stream->close();

		cout << format("Restart Request: %1%") % id << endl;

		stream->connect(host, "http");
		count = 0;
		timer->expires_from_now(posix_time::seconds(interval));
		timer->async_wait(bind(&Request::open, this));
	}
};

int main(int argc, char *argv[]) {
	io_service io;

	for (int i = 0; i < concurrency; i++) {
		Request *req = new Request(io, i);
		req->open();
	}

	io.run();

	return 0;
}