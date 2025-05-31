#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windivert.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "windivert.lib")

// DNS header structure
struct DNSHeader {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
};

// DNS query structure
struct DNSQuestion {
	uint16_t type;
	uint16_t class_;
};

// DNS response structure
struct DNSAnswer {
	uint16_t name;
	uint16_t type;
	uint16_t class_;
	uint32_t ttl;
	uint16_t length;
	uint32_t address;
};

std::string GetWSAErrorString(int errorCode) {
	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&messageBuffer,
		0,
		NULL
	);

	std::string message(messageBuffer, size);
	LocalFree(messageBuffer);

	if (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
		message.pop_back();
		if (!message.empty() && message.back() == '\r') {
			message.pop_back();
		}
	}

	return message;
}

class DNSAnalyzer {
private:
	HANDLE handle;
	std::map<std::string, std::string> redirectMap;

public:
	DNSAnalyzer() : handle(INVALID_HANDLE_VALUE) {
		// Set domains to redirect (example)
		//redirectMap["example.com"] = "127.0.0.1";
		//redirectMap["test.com"] = "192.168.1.100";
	}

	~DNSAnalyzer() {
		if (handle != INVALID_HANDLE_VALUE) {
			WinDivertClose(handle);
		}
	}

	bool Initialize() {
		// Filter to capture only DNS packets
		handle = WinDivertOpen("udp.DstPort == 53 or udp.SrcPort == 53",
			WINDIVERT_LAYER_NETWORK, 0, 0);

		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			std::cerr << "WinDivert initialization failed. Error code: " << error;

			// Provide more specific error information
			switch (error) {
				case ERROR_ACCESS_DENIED:
					std::cerr << " (Access Denied - Administrator privileges required)";
					break;
				case ERROR_INVALID_PARAMETER:
					std::cerr << " (Invalid Parameter - Check filter syntax)";
					break;
				case ERROR_FILE_NOT_FOUND:
					std::cerr << " (WinDivert driver not found)";
					break;
				default:
					std::cerr << " (Unknown error)";
					break;
			}
			std::cerr << std::endl;
			return false;
		}

		std::cout << "DNS analyzer started successfully..." << std::endl;
		return true;
	}

	std::string ParseDomainName(const uint8_t* packet, int offset, int packetLen) {
		std::string domain;
		int pos = offset;
		bool jumped = false;
		int jumps = 0;

		while (pos < packetLen && jumps < 5) {
			uint8_t len = packet[pos];

			if (len == 0) {
				break;
			}

			// Handle compressed names (pointers)
			if ((len & 0xC0) == 0xC0) {
				if (!jumped) {
					offset = pos + 2;
				}
				pos = ((len & 0x3F) << 8) + packet[pos + 1];
				jumped = true;
				jumps++;
				continue;
			}

			pos++;
			if (pos + len > packetLen) break;

			if (!domain.empty()) domain += ".";
			domain += std::string((char*)&packet[pos], len);
			pos += len;
		}

		return domain;
	}

	void AnalyzeDNSPacket(uint8_t* packet, int packetLen, bool isQuery) {
		if (packetLen < sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + sizeof(DNSHeader)) {
			return;
		}

		WINDIVERT_IPHDR* ipHdr = (WINDIVERT_IPHDR*)packet;
		WINDIVERT_UDPHDR* udpHdr = (WINDIVERT_UDPHDR*)(packet + sizeof(WINDIVERT_IPHDR));
		DNSHeader* dnsHdr = (DNSHeader*)(packet + sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR));

		uint16_t questions = ntohs(dnsHdr->questions);
		uint16_t answers = ntohs(dnsHdr->answers);

		if (isQuery && questions > 0) {
			// Analyze DNS query
			int offset = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + sizeof(DNSHeader);
			std::string domain = ParseDomainName(packet, offset, packetLen);

			std::cout << "[DNS Query] Domain: " << domain << std::endl;

			// Check if it's a redirection target
			if (redirectMap.find(domain) != redirectMap.end()) {
				std::cout << "  -> Redirect target: " << domain << " -> " << redirectMap[domain] << std::endl;
			}
		}
		else if (!isQuery && answers > 0) {
			// Analyze DNS response
			int offset = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + sizeof(DNSHeader);
			std::string domain = ParseDomainName(packet, offset, packetLen);

			std::cout << "[DNS Response] Domain: " << domain;

			// Extract IP address from response
			while (offset < packetLen && packet[offset] != 0) {
				if ((packet[offset] & 0xC0) == 0xC0) {
					offset += 2;
					break;
				}
				offset += packet[offset] + 1;
			}
			offset++; // null terminator

			if (offset + sizeof(DNSQuestion) < packetLen) {
				DNSQuestion* question = (DNSQuestion*)(packet + offset);
				offset += sizeof(DNSQuestion);

				// Handle A record response
				if (offset + 12 < packetLen) {
					offset += 2; // name pointer
					uint16_t type = ntohs(*(uint16_t*)(packet + offset));
					offset += 8; // type, class, ttl
					uint16_t dataLen = ntohs(*(uint16_t*)(packet + offset));
					offset += 2;

					if (type == 1 && dataLen == 4 && offset + 4 <= packetLen) { // A record
						uint32_t ip = *(uint32_t*)(packet + offset);
						char ipStr[INET_ADDRSTRLEN];
						if (inet_ntop(AF_INET, &ip, ipStr, INET_ADDRSTRLEN)) {
							std::cout << " -> IP: " << ipStr;
						}
					}
				}
			}
			std::cout << std::endl;
		}
	}

	uint8_t* CreateDNSResponse(uint8_t* originalPacket, int originalLen,
		const std::string& domain, const std::string& newIP, int& newLen) {
		// Calculate new packet size
		newLen = originalLen + sizeof(DNSAnswer);
		uint8_t* newPacket = new uint8_t[newLen];
		memcpy(newPacket, originalPacket, originalLen);

		// Modify IP header
		WINDIVERT_IPHDR* ipHdr = (WINDIVERT_IPHDR*)newPacket;
		WINDIVERT_IPHDR* origIpHdr = (WINDIVERT_IPHDR*)originalPacket;

		// Swap sender and receiver IP
		ipHdr->SrcAddr = origIpHdr->DstAddr;
		ipHdr->DstAddr = origIpHdr->SrcAddr;
		ipHdr->Length = htons(newLen);

		// Modify UDP header
		WINDIVERT_UDPHDR* udpHdr = (WINDIVERT_UDPHDR*)(newPacket + sizeof(WINDIVERT_IPHDR));
		WINDIVERT_UDPHDR* origUdpHdr = (WINDIVERT_UDPHDR*)(originalPacket + sizeof(WINDIVERT_IPHDR));

		uint16_t tempPort = udpHdr->SrcPort;
		udpHdr->SrcPort = origUdpHdr->DstPort;
		udpHdr->DstPort = tempPort;
		udpHdr->Length = htons(newLen - sizeof(WINDIVERT_IPHDR));

		// Modify DNS header
		DNSHeader* dnsHdr = (DNSHeader*)(newPacket + sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR));
		dnsHdr->flags = htons(0x8180); // Response flags
		dnsHdr->answers = htons(1); // One response

		// Add DNS response
		int answerOffset = originalLen;
		DNSAnswer* answer = (DNSAnswer*)(newPacket + answerOffset);
		answer->name = htons(0xC00C); // Compressed name pointer
		answer->type = htons(1); // A record
		answer->class_ = htons(1); // IN class
		answer->ttl = htonl(300); // 5 minute TTL
		answer->length = htons(4); // IPv4 address length

		// IP address conversion
		uint32_t ipAddr;
		if (inet_pton(AF_INET, newIP.c_str(), &ipAddr) == 1) {
			answer->address = ipAddr;
		}
		else {
			// Default value on conversion failure (127.0.0.1)
			uint32_t defaultAddr;
			inet_pton(AF_INET, "127.0.0.1", &defaultAddr);
			answer->address = defaultAddr;
		}

		return newPacket;
	}

	void Run() {
		uint8_t packet[65535];
		UINT packetLen;
		WINDIVERT_ADDRESS addr;

		while (true) {
			if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr)) {
				DWORD error = GetLastError();
				std::cerr << "Failed to receive packet. Error code: " << error << " (" << GetWSAErrorString(error) << ")" << std::endl;
				continue;
			}

			bool isOutbound = addr.Outbound;
			bool isDNSQuery = false;
			std::string queriedDomain;

			if (isOutbound) {
				// Outgoing DNS query
				WINDIVERT_UDPHDR* udpHdr = (WINDIVERT_UDPHDR*)(packet + sizeof(WINDIVERT_IPHDR));
				if (ntohs(udpHdr->DstPort) == 53) {
					isDNSQuery = true;
					AnalyzeDNSPacket(packet, packetLen, true);

					// Extract domain
					int offset = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + sizeof(DNSHeader);
					queriedDomain = ParseDomainName(packet, offset, packetLen);
				}
			}
			else {
				// Incoming DNS response
				WINDIVERT_UDPHDR* udpHdr = (WINDIVERT_UDPHDR*)(packet + sizeof(WINDIVERT_IPHDR));
				if (ntohs(udpHdr->SrcPort) == 53) {
					AnalyzeDNSPacket(packet, packetLen, false);
				}
			}

			// Handle redirection
			if (isDNSQuery && redirectMap.find(queriedDomain) != redirectMap.end()) {
				// Generate fake DNS response
				int responseLen;
				uint8_t* response = CreateDNSResponse(packet, packetLen,
					queriedDomain, redirectMap[queriedDomain], responseLen);

				// Set response direction (inbound)
				WINDIVERT_ADDRESS responseAddr = addr;
				responseAddr.Outbound = 0; // Set to inbound

				// Recalculate checksums
				WinDivertHelperCalcChecksums(response, responseLen, &responseAddr, 0);

				// Send fake response
				if (!WinDivertSend(handle, response, responseLen, NULL, &responseAddr)) {
					DWORD error = GetLastError();
					std::cerr << "Failed to send response. Error code: " << error << " (" << GetWSAErrorString(error) << ")" << std::endl;
				}

				delete[] response;
				std::cout << "Redirection response sent successfully: " << queriedDomain
					<< " -> " << redirectMap[queriedDomain] << std::endl;

				// Block original query (do not send)
				continue;
			}

			// Recalculate checksums
			WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);

			// Retransmit packet
			if (!WinDivertSend(handle, packet, packetLen, NULL, &addr)) {
				DWORD error = GetLastError();
				std::cerr << "Failed to retransmit packet. Error code: " << error << " (" << GetWSAErrorString(error) << ")" << std::endl;
			}
		}
	}

	void AddRedirection(const std::string& domain, const std::string& ip) {
		redirectMap[domain] = ip;
		std::cout << "Redirection added: " << domain << " -> " << ip << std::endl;
	}

	void RemoveRedirection(const std::string& domain) {
		redirectMap.erase(domain);
		std::cout << "Redirection removed: " << domain << std::endl;
	}

	void ShowRedirections() {
		std::cout << "\nCurrent redirection settings:" << std::endl;
		if (redirectMap.empty()) {
			std::cout << "  No redirections configured." << std::endl;
		}
		else {
			for (const auto& pair : redirectMap) {
				std::cout << "  " << pair.first << " -> " << pair.second << std::endl;
			}
		}
		std::cout << std::endl;
	}
};

bool IsElevated() {
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION elevation;
		DWORD dwSize;
		if (GetTokenInformation(hToken, TokenElevation, &elevation,
			sizeof(elevation), &dwSize)) {
			CloseHandle(hToken);
			return elevation.TokenIsElevated != 0;
		}
		CloseHandle(hToken);
	}
	return false;
}



int main() {
	if (!IsElevated()) {
		std::cerr << "ERROR: This program requires administrator privileges to access network interfaces.\n";
		std::cerr << "Please run this program as an administrator and try again.\n";
		return 1;
	}

	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (result != 0) {
		std::cerr << "WSAStartup failed with error code: " << result << std::endl;
		std::cerr << "WSAGetLastError: " << WSAGetLastError() << std::endl;
		std::cerr << "Error description: " << GetWSAErrorString(result) << std::endl;
		return 1;
	}

	DNSAnalyzer analyzer;
	if (!analyzer.Initialize()) {
		std::cerr << "DNS Analyzer initialization failed. Please check error messages above." << std::endl;
		WSACleanup();
		return 1;
	}

	analyzer.ShowRedirections();

	std::cout << "Starting DNS packet monitoring. Press Ctrl+C to exit." << std::endl;
	std::cout << "====================================================" << std::endl;

	try {
		analyzer.Run();
	}
	catch (const std::exception& e) {
		std::cerr << "Exception occurred: " << e.what() << std::endl;
	}
	catch (...) {
		std::cerr << "Unknown exception occurred during execution." << std::endl;
	}

	WSACleanup();
	return 0;
}