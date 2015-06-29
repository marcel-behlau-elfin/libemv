#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#include "include/libemv.h"
#include "internal.h"

SCARDHANDLE hCardHandle;

extern "C" char f_apdu(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
					  unsigned char dataSize, const unsigned char* data,
					  int* outDataSize, unsigned char* outData)
{
	BYTE pbRecv[256] = {0};
	DWORD dwRecv = 256;
	BYTE pbSend[256] = {cla, ins, p1, p2, dataSize};
	memcpy(pbSend + 5, data, dataSize);
	DWORD dwSend = 5 + dataSize;
	LONG lReturn = SCardTransmit(hCardHandle,
		SCARD_PCI_T0,
		pbSend,
		dwSend,
		NULL,
		pbRecv,
		&dwRecv );
	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardTransmit\n");
		return 0;
	}
	if (dwRecv >= 2 && pbRecv[0] == 0x6C)
	{
		BYTE pbSend2[256] = {cla, ins, p1, p2, pbRecv[1]};
		DWORD dwSend = 5;
		dwRecv = 256;
		LONG lReturn = SCardTransmit(hCardHandle,
			SCARD_PCI_T0,
			pbSend2,
			dwSend,
			NULL,
			pbRecv,
			&dwRecv );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			printf("Failed SCardTransmit\n");
			return 0;
		}
	}
	if (dwRecv >= 2 && pbRecv[0] == 0x61)
	{
		BYTE pbSend2[256] = {0x00, 0xC0, 0x00, 0x00, pbRecv[1]};
		DWORD dwSend = 5;
		dwRecv = 256;
		LONG lReturn = SCardTransmit(hCardHandle,
			SCARD_PCI_T0,
			pbSend2,
			dwSend,
			NULL,
			pbRecv,
			&dwRecv );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			printf("Failed SCardTransmit\n");
			return 0;
		}
	}
	memcpy(outData, pbRecv, dwRecv);
	*outDataSize = dwRecv;
	return 1;
}

int main(int argc, char **argv)
{
	SCARDCONTEXT    hSC;
	LONG            lReturn;
	// Establish the context.
	lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
		NULL,
		NULL,
		&hSC);
	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardEstablishContext\n");
		return 1;
	}

	LPTSTR          pmszReaders = NULL;
	DWORD           cch = SCARD_AUTOALLOCATE;	

	lReturn = SCardListReaders(hSC,
		NULL,
		(LPTSTR)&pmszReaders,
		&cch );

	if (lReturn != SCARD_S_SUCCESS || *pmszReaders == '\0')
	{
		printf("No readers\n");
		return 1;
	}
	
	DWORD           dwAP;
	lReturn = SCardConnect( hSC, 
		(LPCTSTR)pmszReaders,
		SCARD_SHARE_SHARED,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
		&hCardHandle,
		&dwAP );
	SCardFreeMemory( hSC, pmszReaders );
	if ( SCARD_S_SUCCESS != lReturn )
	{
		lReturn = SCardReconnect(hCardHandle,
			SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
			SCARD_LEAVE_CARD,
			&dwAP );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			printf("Failed SCardReconnect\n");
			return 1;
		}
	}

	// Use the connection.
	// Display the active protocol.
	switch ( dwAP )
	{
	case SCARD_PROTOCOL_T0:
		printf("Active protocol T0\n"); 
		break;

	case SCARD_PROTOCOL_T1:
		printf("Active protocol T1\n"); 
		break;

	case SCARD_PROTOCOL_UNDEFINED:
	default:
		printf("Active protocol unnegotiated or unknown\n"); 
		break;
	}

	char           szReader[200];
	cch = 200;
	BYTE            bAttr[32];
	DWORD           cByte = 32;
	DWORD           dwState, dwProtocol;

	// Determine the status.
	// hCardHandle was set by an earlier call to SCardConnect.
	lReturn = SCardStatus(hCardHandle,
		szReader,
		&cch,
		&dwState,
		&dwProtocol,
		(LPBYTE)&bAttr,
		&cByte); 

	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardStatus\n");
		return 1;
	}

	// Examine retrieved status elements.
	// Look at the reader name and card state.
	printf("%S\n", szReader );
	switch ( dwState )
	{
	case SCARD_ABSENT:
		printf("Card absent.\n");
		break;
	case SCARD_PRESENT:
		printf("Card present.\n");
		break;
	case SCARD_SWALLOWED:
		printf("Card swallowed.\n");
		break;
	case SCARD_POWERED:
		printf("Card has power.\n");
		break;
	case SCARD_NEGOTIABLE:
		printf("Card reset and waiting PTS negotiation.\n");
		break;
	case SCARD_SPECIFIC:
		printf("Card has specific communication protocols set.\n");
		break;
	default:
		printf("Unknown or unexpected card state. %d\n", dwState);
		break;
	}

 srand (time(NULL));
	libemv_init();

	libemv_set_debug_enabled(1);
	set_function_apdu(f_apdu);

	// Global settings
	LIBEMV_GLOBAL globalSettings = {"12345678", {0x08, 0x40}, {0xC1, 0x00, 0xF0, 0xA0, 0x01}, {0xE0, 0xF8, 0xE8}, 0x22};
	libemv_set_global_settings(&globalSettings);

	LIBEMV_APPLICATIONS visa;
	memset(&visa, 0, sizeof(visa));
	memcpy(visa.RID, "\xA0\x00\x00\x00\x03", 5);
	
	LIBEMV_AID visa1010 = {7, {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10}, 1};
	LIBEMV_AID visa2010 = {7, {0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10}, 1};
	LIBEMV_AID visa2020 = {7, {0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x20}, 1};
	LIBEMV_AID visa8010 = {7, {0xA0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x10}, 1};
	visa.aidsCount = 4;
	visa.aids[0] = visa1010;
	visa.aids[1] = visa2010;
	visa.aids[2] = visa2020;
	visa.aids[3] = visa8010;

	set_applications_data(&visa, 1);

	if (libemv_is_emv_ATR(bAttr, cByte))
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
	lReturn = libemv_authenticate_card();
	printf(" returns %d\n", lReturn);

	return 0;
}
