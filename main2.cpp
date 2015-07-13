#include <ctype.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include "include/libemv.h"
#include "internal.h"

bool libserial_open_device(const char *dev, int *fevdev);
int fd;

static unsigned char compute_bcc(unsigned char *data, int start, int len)
{
	int index = start;
	unsigned char lrc = data[index];
	for(int i = start + 1; i < start + len; i++)
		lrc ^= data[i];
	return lrc;
}

static int recv_packet(unsigned char *data, int *data_len)
{
	fd_set set;
	struct timeval timeout;
	int rb, rv, offset = 0, i, payload_len = 10000;
	unsigned char *packet = (unsigned char *)malloc(4*1024);
	unsigned char bcc;

	//receive operation
	FD_ZERO(&set);
	FD_SET(fd, &set);
	timeout.tv_sec = 0;
	timeout.tv_usec = 2000000;

	//sleep or read
	rv = select(fd + 1, &set, NULL, NULL, &timeout);
	if(rv)
	{
		while(true)
		{
			//read the data
			rb = read(fd, &packet[offset], 4*1024 - offset);
			if(rb > 0)
			{
				offset += rb;

				//starts with STX
				if(packet[0] != 0x02)
				{
					free(packet);
					return 1;
				}

				if(offset >= 3)
					payload_len = packet[2] + packet[1]*256;

				if(offset >= payload_len + 5)
				{
					if(packet[payload_len + 3] != 0x03)
					{
						free(packet);
						return 1;
					}

					memcpy(data, &packet[3], payload_len);
					*data_len = payload_len;

printf("RECV: ");
for(i = 0; i < offset; i++)
	printf("%02X ", packet[i]);
printf("\n");

					bcc = compute_bcc(packet, 1, payload_len + 3);
					if(bcc != packet[4 + payload_len])
					{
						printf("Bad BCC %02X != %02X\n", bcc, packet[4 + payload_len]);
						return 1;
					}

					free(packet);
					return 0;
				}
			}
		}
	}
	else
	{
		free(packet);
		return 1;
	}
}

static void send_packet(unsigned char cmd, unsigned char *data, int data_len)
{
	int packet_len = data_len + 6;
	unsigned char *packet = (unsigned char *)malloc(packet_len);

	packet[0] = 0x02;
	packet[1] = ((data_len + 1) >> 8) & 0xFF;
	packet[2] = ((data_len + 1) >> 0) & 0xFF;
	packet[3] = cmd;
	if(data != NULL && data_len > 0)
		memcpy(&packet[4], data, data_len);
	packet[4 + data_len] = 0x03;
	packet[5 + data_len] = compute_bcc(packet, 1, packet_len - 2);

	printf("SEND (%d): ", data_len);
	for(int i = 0; i < packet_len; i++)
		printf("%02X ", packet[i]);
	printf("\n");

	write(fd, packet, packet_len);
	free(packet);
}

static int send_command(unsigned char cmd, unsigned char *data, int data_len, unsigned char *resp, int *resp_len)
{
	send_packet(cmd, data, data_len);
	return recv_packet(resp, resp_len);
}

static int icc_reset(unsigned char *atr, int *atr_len)
{
	unsigned char response[1024];
	int response_len;

	if(send_command(0x52, NULL, 0, response, &response_len))
	{
		return -1;
	}
	else if(response[0] == 0x50)
	{
		*atr_len = response_len - 2;
		memcpy(atr, &response[2], *atr_len);
		return 0;
	}
	else
	{
		return -1;
	}
}

static int read_track(char *track_data)
{
	unsigned char response[1024];
	int response_len, i;
	char *ptr = track_data;

	if(send_command(0x4D, NULL, 0, response, &response_len))
	{
		return -1;
	}
	else if(response[0] == 0x50)
	{
		char prefix[] = { '%', ';', ';' };
		int index = 0;
 
		//start the first track
		*ptr++ = prefix[index++];

		for(i = 2; i < response_len; i++)
		{
			if(response[i] == 0x00)
			{
				//end last track
				if(index > 0)
					*ptr++ = '?';

				//start this track
				*ptr++ = prefix[index++];

				//only process 3 tracks
				if(index == 3)
					break;
				else
					continue;
			}
			else
			{
				*ptr++ = response[i];
			}
		}

		//don't include blank tracks
		while(*(ptr - 1) == ';')
			ptr--;

		*ptr++ = 0x00;
		return 0;
	}
	else
	{
		printf("Invalid response %02X\n", response[0]);
		return -1;
	}
}

static int clear_track()
{
	unsigned char response[128];
	int response_len;

	if(send_command(0x43, NULL, 0, response, &response_len))
		return -1;
	else if(response[0] == 0x50)
		return 0;
	else
		return -1;
}

static int eject_card()
{
	unsigned char response[128];
	int response_len;

	if(send_command(0x45, NULL, 0, response, &response_len))
		return -1;
	else if(response[0] == 0x50)
		return 0;
	else
		return -1;
}

static int get_status()
{
	unsigned char response[128];
	int response_len;

	if(send_command(0x53, NULL, 0, response, &response_len))
		return 1;
	else if(response[0] == 0x50)
		return response[1];
	else
		return 1;
}

extern "C" char f_apdu(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
					  unsigned char dataSize, const unsigned char* data,
					  int* outDataSize, unsigned char* outData)
{
	unsigned char adpu_packet[4096], response[4096];
	int adpu_packet_len, response_len;

	adpu_packet[0] = cla;
	adpu_packet[1] = ins;
	adpu_packet[2] = p1;
	adpu_packet[3] = p2;
	adpu_packet[4] = dataSize;

	if(dataSize > 0)
	{
		memcpy(&adpu_packet[5], data, dataSize);
		adpu_packet_len = 5 + dataSize;
	}
	else
	{
		//if we have no data then set Le to 0x00
		adpu_packet[5] = 0x00;
		adpu_packet_len = 6;
	}

	//send the command
	if(send_command(0x49, adpu_packet, adpu_packet_len, response, &response_len))
		return 0;

	if(response[0] == 0x50)
	{
		*outDataSize = response_len - 2;
		memcpy(outData, &response[2], response_len - 2);
		return 1;
	}

	//invalid response
	return 0;
}

int main(int argc, char **argv)
{
	unsigned char response[4096];
	int x, response_len, status;
	unsigned char battr[4096];
	int battr_len;
	char track_data[1024];

	if(!libserial_open_device("/dev/hardware/kemv", &fd))
	{
		printf("can't not open emv device\n");
		return 1;
	}

	if(send_command(0x56, NULL, 0, response, &response_len))
	{
		close(fd);
		printf("can't query emv device\n");
		return 1;
	}

	status = get_status();
	printf("emv card status: %02X\n", status);

	if((status & 0x80) != 0x80)
	{
		close(fd);
		printf("card not inserted\n");
		return 1;
	}

	if(icc_reset(battr, &battr_len) != 0)
	{
		read_track(track_data);
		close(fd);
		printf("invalid ICC emv card, track_data = %s\n", track_data);
		return 1;
	}

	printf("ATR (%d): ", battr_len);
	for(x = 0; x < battr_len; x++)
		printf("%02X ", battr[x]);
	printf("\n");

	srand(time(NULL));
	libemv_init();

	libemv_set_debug_enabled(1);
	set_function_apdu(f_apdu);

	// Global settings
	LIBEMV_GLOBAL globalSettings = {"12345678", {0x08, 0x40}, {0xC1, 0x00, 0xF0, 0xA0, 0x01}, {0xE0, 0xF8, 0xE8}, 0x22};
	libemv_set_global_settings(&globalSettings);

	LIBEMV_APPLICATIONS visa;
	memset(&visa, 0, sizeof(visa));
	LIBEMV_AID a = { 7, { 0xA0, 0x00, 0x00, 0x06, 0x20, 0x06, 0x20 }, 1};   //COMMON U.S DEBIT - DEBIT NETWORK ALLIANCE (DNA)
	LIBEMV_AID b = { 7, { 0xA0, 0x00, 0x00, 0x00, 0x98, 0x08, 0x40 }, 1};   //COMMON U.S DEBIT - VISA
 	LIBEMV_AID c = { 7, { 0xA0, 0x00, 0x00, 0x01, 0x52, 0x40, 0x10 }, 1};   //COMMON U.S DEBIT - DISCOVER
 	LIBEMV_AID d = { 7, { 0xA0, 0x00, 0x00, 0x00, 0x04, 0x22, 0x03 }, 1};   //COMMON U.S DEBIT - MASTERCARD MAESTRO
 	LIBEMV_AID e = { 7, { 0xA0, 0x00, 0x00, 0x02, 0x77, 0x10, 0x10 }, 1};   //INTERAC
 	LIBEMV_AID f = { 6, { 0xA0, 0x00, 0x00, 0x00, 0x25, 0x01 }, 1};         //AMERICAN EXPRESS
 	LIBEMV_AID g = { 7, { 0xA0, 0x00, 0x00, 0x00, 0x65, 0x10, 0x10 }, 1};   //JAPAN CREDIT BUREAU
 	LIBEMV_AID h = { 7, { 0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10 }, 1};   //DISCOVER
 	LIBEMV_AID i = { 7, { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x10 }, 1};   //PLUS a;
 	LIBEMV_AID j = { 7, { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10 }, 1};   //VISA ELECTRON
 	LIBEMV_AID k = { 7, { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10 }, 1};   //VISA CREDIT OR DEBIT
 	LIBEMV_AID l = { 7, { 0xA0, 0x00, 0x00, 0x00, 0x04, 0x60, 0x00 }, 1};   //CIRRUS
 	LIBEMV_AID m = { 7, { 0xA0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60 }, 1};   //MAESTRO - DEBIT
 	LIBEMV_AID n = { 7, { 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10 }, 1};   //MASTER CREDIT OR DEBIT

	visa.aidsCount = 14;
	visa.aids[0] = a;
	visa.aids[1] = b;
	visa.aids[2] = c;
	visa.aids[3] = d;
	visa.aids[4] = e;
	visa.aids[5] = f;
	visa.aids[6] = g;
	visa.aids[7] = h;
	visa.aids[8] = i;
	visa.aids[9] = j;
	visa.aids[10] = k;
	visa.aids[11] = l;
	visa.aids[12] = m;
	visa.aids[13] = n;

	set_applications_data(&visa, 1);

	if (libemv_is_emv_ATR(battr, battr_len))
		printf("ATR ok.\n");
	else
		printf("ATR wrong.\n");

	int resultBuildCand = libemv_build_candidate_list();
	if (resultBuildCand != LIBEMV_OK)
		return 0;

	while (1)
	{
		int resultSelectApplication = libemv_application_selection();
		if (resultSelectApplication < 0)
			return 0;
		
		if (resultSelectApplication == LIBEMV_NEED_CONFIRM_APPLICATION)
		{
			printf("Confirm select app %s (y/n): ", libemv_get_candidate(0)->strApplicationLabel);
			if (getchar() != 'y')
				return 0;
			if (libemv_select_application(0) != LIBEMV_OK)
				continue;
		}
		
		if (resultSelectApplication == LIBEMV_NEED_SELECT_APPLICATION)
		{
			printf("Select application from list:\n");
			for (int idx = 0; idx < libemv_count_candidates(); idx++)
			{
				printf("%d (priority %d) - %s\n", idx, libemv_get_candidate(idx)->priority, libemv_get_candidate(idx)->strApplicationLabel);
			}
			printf("Index: ");
			int indexSelect = getchar() - '0';
			if (libemv_select_application(indexSelect) != LIBEMV_OK)
				continue;
		}

		// Application selected ok, get processing option
		int resultProcessingOption = libemv_get_processing_option();
		if (resultProcessingOption != LIBEMV_OK)
			continue;

		break;
	}

	int resultReadApp = libemv_read_app_data();
	if (resultReadApp != LIBEMV_OK)
		return 0;

	// Debug out buffer
	{
		int shift = 0;
		unsigned short tag;
		unsigned char* data;
		int length;
		printf("\nApp buffer:\n");
		while ((shift = libemv_get_next_tag(shift, &tag, &data, &length)) != 0)
		{
			const char *type;
			switch(tag)
			{
				case TAG_FCI_TEMPLATE: type = "TAG_FCI_TEMPLATE"; break;
				case TAG_DF_NAME: type = "TAG_DF_NAME"; break;
				case TAG_FCI_PROP_TEMPLATE: type = "TAG_FCI_PROP_TEMPLATE"; break;
				case TAG_SFI_OF_DEF: type = "TAG_SFI_OF_DEF"; break;
				case TAG_LANGUAGE_PREFERENCE: type = "TAG_LANGUAGE_PREFERENCE"; break;
				case TAG_ISSUER_CODE_TABLE_INDEX: type = "TAG_ISSUER_CODE_TABLE_INDEX"; break;
				case TAG_FCI_ISSUER_DISCR_DATA: type = "TAG_FCI_ISSUER_DISCR_DATA"; break;
				case TAG_APPLICATION_LABEL: type = "TAG_APPLICATION_LABEL"; break;
				case TAG_APP_PRIORITY_INDICATOR: type = "TAG_APP_PRIORITY_INDICATOR"; break;
				case TAG_PDOL: type = "TAG_PDOL"; break;
				case TAG_TVR: type = "TAG_TVR"; break;
				case TAG_TSI: type = "TAG_TSI"; break;
				case TAG_APPLICATION_TEMPLATE: type = "TAG_APPLICATION_TEMPLATE"; break;
				case TAG_ADF_NAME: type = "TAG_ADF_NAME"; break;
				case TAG_APP_PREFERRED_NAME: type = "TAG_APP_PREFERRED_NAME"; break;
				case TAG_TERMINAL_CAPABILITIES: type = "TAG_TERMINAL_CAPABILITIES"; break;
				case TAG_ADDI_TERMINAL_CAPABILITIES: type = "TAG_ADDI_TERMINAL_CAPABILITIES"; break;
				case TAG_AID: type = "TAG_AID"; break;
				case TAG_IFD_SERIAL_NUMBER: type = "TAG_IFD_SERIAL_NUMBER"; break;
				case TAG_TERMINAL_COUNTRY_CODE: type = "TAG_TERMINAL_COUNTRY_CODE"; break;
				case TAG_TERMINAL_TYPE: type = "TAG_TERMINAL_TYPE"; break;
				case TAG_ACQUIRER_ID: type = "TAG_ACQUIRER_ID"; break;
				case TAG_APPLICATION_VERSION_NUMBER: type = "TAG_APPLICATION_VERSION_NUMBER"; break;
				case TAG_MCC: type = "TAG_MCC"; break;
				case TAG_MERCHANT_ID: type = "TAG_MERCHANT_ID"; break;
				case TAG_MERCHANT_NAME_AND_LOCATION: type = "TAG_MERCHANT_NAME_AND_LOCATION"; break;
				case TAG_TERMINAL_FLOOR_LIMIT: type = "TAG_TERMINAL_FLOOR_LIMIT"; break;
				case TAG_TERMINAL_ID: type = "TAG_TERMINAL_ID"; break;
				case TAG_RISK_MANAGEMENT_DATA: type = "TAG_RISK_MANAGEMENT_DATA"; break;
				case TAG_TRANSACTION_REFERENCE_CURRENCY: type = "TAG_TRANSACTION_REFERENCE_CURRENCY"; break;
				case TAG_TRANSACTION_REFERENCE_EXPONENT: type = "TAG_TRANSACTION_REFERENCE_EXPONENT"; break;
				case TAG_AIP: type = "TAG_AIP"; break;
				case TAG_AFL: type = "TAG_AFL"; break;
				case TAG_COMMAND_TEMPLATE: type = "TAG_COMMAND_TEMPLATE"; break;
				case TAG_RESPONSE_FORMAT_1: type = "TAG_RESPONSE_FORMAT_1"; break;
				case TAG_RESPONSE_FORMAT_2: type = "TAG_RESPONSE_FORMAT_2"; break;
				case TAG_READ_RECORD_RESPONSE_TEMPLATE: type = "TAG_READ_RECORD_RESPONSE_TEMPLATE"; break;
				case TAG_APPLICATION_EXP_DATE: type = "TAG_APPLICATION_EXP_DATE"; break;
				case TAG_PAN: type = "TAG_PAN"; break;
				case TAG_CDOL_1: type = "TAG_CDOL_1"; break;
				case TAG_CDOL_2: type = "TAG_CDOL_2"; break;
				case TAG_TRACK1: type = "TAG_TRACK1"; break;
				case TAG_TRACK2: type = "TAG_TRACK2"; break;
				case TAG_APPLICATION_EFFECTIVE_DATE: type = "TAG_APPLICATION_EFFECTIVE_DATE"; break;
				case TAG_TXN_CURRENCY_CODE: type = "TAG_TXN_CURRENCY_CODE"; break;
				case TAG_SERVICE_CODE: type = "TAG_SERVICE_CODE"; break;
				case TAG_APPLICATION_PSN: type = "TAG_APPLICATION_PSN"; break;
				case TAG_TXN_CURRENCY_EXPONENT: type = "TAG_TXN_CURRENCY_EXPONENT"; break;
				case TAG_ACCOUNT_TYPE: type = "TAG_ACCOUNT_TYPE"; break;
				case TAG_CVM_LIST: type = "TAG_CVM_LIST"; break;
				case TAG_CERTIFICATE_AUTH_PKI: type = "TAG_CERTIFICATE_AUTH_PKI"; break;
				case TAG_ISSUER_PUBLIC_KEY_CERTIFICATE: type = "TAG_ISSUER_PUBLIC_KEY_CERTIFICATE"; break;
				case TAG_ISSUER_PUBLIC_KEY_REMAINDER: type = "TAG_ISSUER_PUBLIC_KEY_REMAINDER"; break;
				case TAG_ISSUER_ACTION_CODE_DEFAULT: type = "TAG_ISSUER_ACTION_CODE_DEFAULT"; break;
				case TAG_ISSUER_ACTION_CODE_DENIAL: type = "TAG_ISSUER_ACTION_CODE_DENIAL"; break;
				case TAG_ISSUER_ACTION_CODE_ONLINE: type = "TAG_ISSUER_ACTION_CODE_ONLINE"; break;
				case TAG_ICC_PUBLIC_KEY_CERTIFICATE: type = "TAG_ICC_PUBLIC_KEY_CERTIFICATE"; break;
				case TAG_ICC_PUBLIC_KEY_EXPONENT: type = "TAG_ICC_PUBLIC_KEY_EXPONENT"; break;
				case TAG_ICC_PUBLIC_KEY_REMAINDER: type = "TAG_ICC_PUBLIC_KEY_REMAINDER"; break;
				case TAG_SDA: type = "TAG_SDA"; break;
				case TAG_SDAD: type = "TAG_SDAD"; break;
				case TAG_APPLICATION_CURRENCY_CODE: type = "TAG_APPLICATION_CURRENCY_CODE"; break;
				case TAG_APPLICATION_CURRENCY_EXPONENT: type = "TAG_APPLICATION_CURRENCY_EXPONENT"; break;
				case TAG_TRACK1_DISC_DATA: type = "TAG_TRACK1_DISC_DATA"; break;
				case TAG_TRACK2_DISC_DATA: type = "TAG_TRACK2_DISC_DATA"; break;
				case TAG_ISSUER_COUNTRY_CODE: type = "TAG_ISSUER_COUNTRY_CODE"; break;
				case TAG_APPLICATION_USAGE_CONTROL: type = "TAG_APPLICATION_USAGE_CONTROL"; break;
				case TAG_DDOL: type = "TAG_DDOL"; break;
				case TAG_CARDHOLDER_NAME: type = "TAG_CARDHOLDER_NAME"; break;
				case TAG_ISSUER_PUBLIC_KEY_EXPONENT: type = "TAG_ISSUER_PUBLIC_KEY_EXPONENT"; break;
				default: type = "UNKNOWN"; break;
			}

			bool isAscii = true;
			printf("- %4X [%s] [%d]: {", tag, type, length);
			for (int idx = 0; idx < length; idx++)
			{
				printf("%02X, ", data[idx] & 0xFF);
				if (data[idx] < ' ' || data[idx] > 0x7E)
					isAscii = false;
			}
			printf("}\n");
			if (isAscii)
			{
				char* strData = (char *)malloc(length + 1);
				strData[length] = 0;
				memcpy(strData, data, length);
				printf("ascii: %s\n", strData);
				free(strData);
			}
		}
	}

	printf("running card authentication\n");
	if(libemv_process_offline_authenticate() != 0)
		return 1;

	printf("running restrictions\n");
	if(libemv_process_restrictions() != 0)
		return 1;

	printf("running risk management\n");
	if(libemv_process_risk_management() != 0)
		return 1;

	printf("running cardholder verification\n");
	if(libemv_process_cardholder_verification() != 0)
		return 1;

	printf("processing transaction\n");
	if(libemv_process_transaction_decision() != 0)
		return 1;

	printf("TRANSACTION COMPLETE\n");
	return 0;
}

bool libserial_open_device(const char *dev, int *fevdev)
{
	int fd, speed;
	struct termios tty;
	char dev_mode[100];
	char buffer[100] = { 0 };

	*fevdev = open(dev, O_RDWR | O_NOCTTY | O_SYNC);
	if(*fevdev == -1)
		return false;

	//read the contents of the mode file (e.g. 8N1 115200)
	sprintf(dev_mode, "%s_mode", dev);
	fd = open(dev_mode, O_RDONLY);
	if(fd == -1) return false;
	if(read(fd, buffer, 100) <= 0) return false;
	close(fd);

	//trim
	while(isspace(buffer[strlen(buffer)-1]))
		buffer[strlen(buffer)-1] = 0x00;

	//get current tty settings
	memset(&tty, 0, sizeof tty);
	if(tcgetattr(*fevdev, &tty) != 0)
	{
		close(*fevdev);
		return false;
	}

	//turn off break, etc, and set up for zero/low timeout
	cfmakeraw(&tty);
	tty.c_iflag &= ~IGNBRK;
	tty.c_lflag = 0;
	tty.c_oflag = 0;
	tty.c_cc[VMIN] = 0;
	tty.c_cc[VTIME] = 1;
	tty.c_iflag &= ~(IXON | IXOFF | IXANY);
	tty.c_cflag |= (CLOCAL | CREAD);
	tty.c_cflag &= ~CRTSCTS;

	//compute the proper settings for communication
	if(strstr(buffer, "8N1") == buffer)
	{
		tty.c_cflag &= ~(PARENB | PARODD);
		tty.c_cflag &= ~CSTOPB;
		tty.c_cflag &= ~CSIZE;
		tty.c_cflag |= CS8;
	}
	else if(strstr(buffer, "7E1") == buffer)
	{
		tty.c_cflag |= PARENB;
		tty.c_cflag &= ~PARODD;
		tty.c_cflag &= ~CSTOPB;
		tty.c_cflag &= ~CSIZE;
		tty.c_cflag |= CS7;
	}
	else if(strstr(buffer, "7O1") == buffer)
	{
		tty.c_cflag |= PARENB;
		tty.c_cflag |= PARODD;
		tty.c_cflag &= ~CSTOPB;
		tty.c_cflag &= ~CSIZE;
		tty.c_cflag |= CS7;
	}
	else
	{
		//not a valid serial device
		close(*fevdev);
		return false;
	}

	//find the space and skip to the baud rate
	char *baud = strstr(buffer, " ") + 1;
	if(strcmp(baud, "115200") == 0)
	{
		speed = B115200;
	}
	else if(strcmp(baud, "57600") == 0)
	{
		speed = B57600;
	}
	else if(strcmp(baud, "38400") == 0)
	{
		speed = B38400;
	}
	else if(strcmp(baud, "19200") == 0)
	{
		speed = B19200;
	}
	else if(strcmp(baud, "9600") == 0)
	{
		speed = B9600;
	}
	else
	{
		close(*fevdev);
		return false;
	}

	//set the speed
	cfsetospeed(&tty, speed);
	cfsetispeed(&tty, speed);

	//set the tty attrs
	if(tcsetattr(*fevdev, TCSANOW, &tty) != 0)
	{
		close(*fevdev);
		return false;
	}
	
	return true;
}

void libserial_close_device(int fd)
{
	//release the device
	close(fd);
}
