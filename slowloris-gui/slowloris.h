#ifndef _SLOWLORIS_H_
#define _SLOWLORIS_H_

#include <fstream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/thread/thread.hpp>

using namespace std;
using namespace boost;
using namespace asio;

typedef map<string, string> Options;

void launchSlowloris(Options option);
void requestFactory(io_service* io, deadline_timer* timer, int id);

class Request {
public:
	Request(io_service& io, int id);
	~Request();

	void start();
	void append();
	void finish();
	void close();

private:
	deadline_timer* timer;
	ip::tcp::iostream* stream;
	int id;
	int count;

};

#endif // _SLOWLORIS_H_
