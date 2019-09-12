#pragma once
#include "ConsoleLogger.h"


int main() {
	PktCapRetrunType result;
	PacketCapture pkt;
	int select;

	result = pkt.ShowNetworkDeviceList();

	if (result == PktCapRetrunType::NO_DEVICE) {
		std::cout << "NO_DEIVCE";
		return -1;
	}
	else {
		std::cout << "FUNC_ERROR";
		return -1;
	}

	std::cout << "Select device>";
	std::cin >> select;

	result = pkt.OpenNetworkDevice(select);
	if (result == PktCapRetrunType::FAILED_TO_OPEN_DEVICE) {
		std::cout << "FAILED_TO_OPEN_DEVICE";
		return -1;
	}

	else if (result == PktCapRetrunType::INVALID_INPUT) {
		std::cout << "INVLAID_INPUT";
		return -1;
	}
	else {
		std::cout << "FUNC_ERROR";
		return -1;
	}
	getchar();
	return 0;
}