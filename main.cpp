#include <stdint.h>
#include <string>
#include <iostream>
#include <algorithm>
#include <boost/asio.hpp>
#include <boost/asio/serial_port.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/bind.hpp>
#include <boost/thread.hpp>

boost::posix_time::time_duration::tick_type milliseconds_since_epoch()
{
	using boost::gregorian::date;
	using boost::posix_time::ptime;
	using boost::posix_time::microsec_clock;

	static ptime const epoch(date(1970, 1, 1));
	return (microsec_clock::universal_time() - epoch).total_milliseconds();
}

std::string packetToStr(const std::string& s) {
	std::string out;	
	for (int i = 0; i < s.length(); ++i) {
		if (s[i] >= ' ' && s[i] <= '~') {
			out += s[i];
		} else {
			char str[5];
			sprintf(str, "\\x%02x", (uint8_t)s[i]);
			out += str;
		}
	}
	return out;
}

class CaptureFile {
public:
	explicit CaptureFile(const std::string& fileName) : fileName_(fileName) {
		writeGlobalHeader();
	}
	
	void writePacket(const std::string& packet, char dir) {
		boost::mutex::scoped_lock scoped_lock(mutex_);
		printf("%c%d %s\n", (dir==0) ? '<' : '>', (int)packet.length(), packetToStr(packet).c_str());
		uint64_t nowMs = milliseconds_since_epoch();
		std::string hdlcPayload = decodeHdlc(packet);
		//printf("HDLC: %s\n", packetToStr(hdlcPayload).c_str());
		FILE* file = fopen(fileName_.c_str(), "ab");
		uint32_t ui = nowMs / 1000;
		fwrite(&ui, sizeof(ui), 1, file);
		ui = (nowMs % 1000) * 1000;
		fwrite(&ui, sizeof(ui), 1, file);
		ui = hdlcPayload.length() - 4 + 1;
		fwrite(&ui, sizeof(ui), 1, file);
		fwrite(&ui, sizeof(ui), 1, file);
		fwrite(&dir, sizeof(dir), 1, file);
		fwrite(hdlcPayload.c_str() + 1, ui - 1, 1, file);
		fclose(file);
	}

private:
	static std::string decodeHdlc(const std::string& packet) {
		return decodeHdlc(packet.begin(), packet.end());
	}
	
	template<class InIter>
	static std::string decodeHdlc(InIter pos, InIter end) {
		std::string result;
		if (pos == end) return result;
		result += *pos++;
		bool escape = false;
		for (; pos != end && *pos != '~'; ++pos) {
			char c = *pos;
			if (c == '}') {
				escape = true;
			} else {
				if (escape)
					c ^= 0x20;
				escape = false;
				result += c;
			}
		}
		result += *pos++;
		return result;
	}

	void writeGlobalHeader() {
		FILE* file = fopen(fileName_.c_str(), "wb");
		uint32_t ui = 0xa1b2c3d4;
		uint16_t us = 2;
		fwrite(&ui, sizeof(ui), 1, file); // magic
		fwrite(&us, sizeof(us), 1, file); // major
		us = 4;
		fwrite(&us, sizeof(us), 1, file); // minor
		ui = 0;
		fwrite(&ui, sizeof(ui), 1, file); // thiszone
		ui = 0;
		fwrite(&ui, sizeof(ui), 1, file); // sigfigs
		ui = 65535;
		fwrite(&ui, sizeof(ui), 1, file); // snaplength
		ui = 204;
		fwrite(&ui, sizeof(ui), 1, file); // network
		fclose(file);
	}

	std::string fileName_;
	boost::mutex mutex_;
};


class Serial {
	char read_msg_[512];
	boost::asio::io_service m_io;
	boost::asio::serial_port m_port;
	std::string devName_;
	std::string buffer_;
	CaptureFile* out_;
	char dir_;
private:
    void handler(const boost::system::error_code& error, size_t bytes_transferred) {
		buffer_.append(read_msg_, &read_msg_[bytes_transferred]);
		for (;;) {
			size_t begin = buffer_.find('~');
			if (begin == std::string::npos) {
				buffer_.clear();
				break;
			}
			size_t end = buffer_.find('~', begin+1);
			if (end == std::string::npos) break;
			// capture frame
			if (out_ && end - begin > 4)
				out_->writePacket(buffer_.substr(begin, end - begin + 1), dir_);
			buffer_.erase(0, end);
		}      
		read_some();
	}

	void read_some() {
	  m_port.async_read_some(boost::asio::buffer(read_msg_,512),
		  boost::bind(&Serial::handler, this,
			boost::asio::placeholders::error, 
			boost::asio::placeholders::bytes_transferred) );
	}

public:
	Serial(const char *dev_name, int baud = 115200, CaptureFile* out = NULL, char dir = 0) : m_io(), m_port(m_io, dev_name), devName_(dev_name), out_(out), dir_(dir) {
/*    
      port.set_option( boost::asio::serial_port_base::parity() );	// default none
      port.set_option( boost::asio::serial_port_base::character_size( 8 ) );
      port.set_option( boost::asio::serial_port_base::stop_bits() );	// default one
      port.set_option( boost::asio::serial_port_base::baud_rate( baud_rate ) );
*/
		m_port.set_option( boost::asio::serial_port_base::parity() );	// default none
		m_port.set_option( boost::asio::serial_port_base::baud_rate( baud ) );
		read_some();
      
		// how is this asynch? only because I shove it to thread?! Hm...
		boost::thread t(boost::bind(&boost::asio::io_service::run, &m_io));		
	}
};

/* serial DTE DCE FILE */

int main(int argc, char* argv[]) {
	int baud = 115200;
	std::string outFile("ppp.pcap");
	if (argc < 3) {
		std::cout << argv[0] << " DTE-serial-port DCE-serial-port [-bBaudrate] [-oOutFile]\n";
		std::cout << "e.g. " << argv[0] << " /dev/ttyS0 /dev/ttyS1 -ocapture.pcap (Linux) default baudrate=" << baud << "\n";
		std::cout << "     " << argv[0] << " COM1 COM2 -b115200 (Windows) default outFile=" << outFile << "\n";
		std::cout << "pcap file can be read by Wireshark\n";
		return 0;
	}
	std::string dteSerial(argv[1]);
	std::string dceSerial(argv[2]);
	for (int i = 3; i < argc; ++i) {
		const char* arg = argv[i];
		if(arg[0]!='-') continue;
		switch(arg[1]) {
			case 'b':
				baud = atoi(&arg[2]);
				break;
			case 'o':
				outFile = &arg[2];
				break;
		}
	}
	CaptureFile cap(outFile);
	std::cout << "DTE:     " << argv[1] << " symbol'<'\n";
	std::cout << "DCE:     " << argv[2] << " symbol'>'\n";
	std::cout << "baud:    " << baud << "\n";
	std::cout << "outFile: " << outFile << "\n";
	Serial s1(dteSerial.c_str(), baud, &cap, 0);
	Serial s2(dceSerial.c_str(), baud, &cap, 1);

	//boost::this_thread::sleep(boost::posix_time::milliseconds(60*1000));
	std::cout << "Press enter to exit\n";
	getchar();
      
	return 0;
}
