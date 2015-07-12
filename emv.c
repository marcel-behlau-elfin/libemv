#include "include/libemv.h"
#include "internal.h"
#include "nn.h"
#include "sha1.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

EMV_BITS* libemv_TSI;
EMV_BITS* libemv_TVR;
EMV_BITS* libemv_capa;
EMV_BITS* libemv_addi_capa;
EMV_BITS* libemv_AIP;
static unsigned char static_data_to_be_auth[10*1024];
static int static_data_to_be_auth_len = 0;
static int transaction_number = 1;

extern EMV_RID_MODULUS libemv_public_modulus[];
extern int libemv_public_modulus_count;

static int read_issuer_public_key(unsigned char *key, int *key_size);
static int read_icc_public_key(unsigned char *key, int *key_size);
static int verify_sda(void);
static int verify_dda(void);

static void tobcd(unsigned long long value, unsigned char *val, int len)
{
	int i, lower = 1, offset;

	for(i = 0; i < len; i++)
		val[i] = 0x00;

	offset = len - 1;
	while(value > 0)
	{
		int kar = value % 10;
		value = value / 10;

		if(lower)
		{
			val[offset] |= (kar << 0);
			lower = 0;
		}
		else
		{
			val[offset] |= (kar << 4);
			lower = 1;
			offset--;
		}
	}
}

LIBEMV_API char libemv_is_emv_ATR(unsigned char* bufATR, int size)
{
	if (size < 4)
		return 0;

	if (bufATR[0] != 0x3B && bufATR[0] != 0x3F)
		return 0;

	if ((bufATR[1] >> 4) == 0x06)
	{
		// T0 protocol
		if (bufATR[2] != 0x00)
			return 0;

		return 1;
	} else if ((bufATR[1] >> 4) == 0x0E)
	{
		// T1 protocol
		if (size < 9)
			return 0;
		if (bufATR[2] != 0x00)
			return 0;
		if (bufATR[4] != 0x81)
			return 0;
		if (bufATR[5] != 0x31)
			return 0;
		if (bufATR[6] < 0x10 || bufATR[6] > 0xFE)
			return 0;

		return 1;
	}

	// bufATR[1] wrong
	return 0;
}

char libemv_apdu(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
				 unsigned char dataSize, const unsigned char* data,
				 int* outDataSize, unsigned char* outData)
{
	char res;
	if (libemv_debug_enabled)
	{
		int i;
		libemv_printf("C-APDU: %02X %02X %02X %02X; %02X ", cla & 0xFF, ins & 0xFF, p1 & 0xFF, p2 & 0xFF, dataSize & 0xFF);
		for (i = 0; i < dataSize; i++)
			libemv_printf("%02X", data[i] & 0xFF);
		libemv_printf("\n");
	}
	res = libemv_ext_apdu(cla, ins, p1, p2, dataSize, data, outDataSize, outData);
	if (!res)
	{
		libemv_printf("libemv_ext_apdu failed, transmission error\n");
		return res;
	}

	// Response data must at least have SW1 SW2
	if (*outDataSize < 2)
	{
		libemv_printf("Response apdu wrong size\n");
		return 0;
	}
	if (libemv_debug_enabled)
	{
		int i;
		libemv_printf("R-APDU: ");
		for (i = 0; i < *outDataSize - 2; i++)
			libemv_printf("%02X", outData[i] & 0xFF);
		libemv_printf("; %02X %02X", outData[*outDataSize - 2] & 0xFF, outData[*outDataSize - 1] & 0xFF);
		libemv_printf("\n");
	}
	return res;
}

// Candidate applications
#define MAX_CANDIDATE_APPLICATIONS 20
static LIBEMV_SEL_APPLICATION_INFO candidateApplications[MAX_CANDIDATE_APPLICATIONS];
static int candidateApplicationCount;
static int indexApplicationSelected;

// Check DF in application list (and check ASI)
static char check_candidate_in_app_list(LIBEMV_SEL_APPLICATION_INFO* candidate);

// Process data from SELECT ADF response
// Return LIBEMV_OK or error
static int select_adf_parse(unsigned char* rApdu, int rApduSize, LIBEMV_SEL_APPLICATION_INFO* appInfo);

// Re-init data of application buffer, need before every transaction
static void zeroizeAppBuffer(void);

LIBEMV_API int libemv_build_candidate_list(void)
{
	unsigned short endianNumber;
	char isBigEndian;

	// Detect endiannes
	endianNumber = 1; /* 0x0001 */
	isBigEndian = *((unsigned char *) &endianNumber) == 0 ? 1 : 0;

	if (isBigEndian)
	{
		#ifndef BIG_ENDIAN
			libemv_printf("Your system is big endian model, please compile with define BIG_ENDIAN\n");
			return LIBEMV_UNKNOWN_ERROR;
		#endif
	}

	zeroizeAppBuffer();
	candidateApplicationCount = 0;
	indexApplicationSelected = 0;

	// Try to use PSE method
	// SELECT ‘1PAY.SYS.DDF01’
	if (libemv_settings.appSelectionUsePSE)
	{
		int outSize;
		unsigned char outData[256];
		if (libemv_debug_enabled)
			libemv_printf("Try to select 1PAY.SYS.DDF01\n");
		if (!libemv_apdu(0x00, 0xA4, 0x04, 0x00, 14, "1PAY.SYS.DDF01", &outSize, outData))
			return LIBEMV_ERROR_TRANSMIT;
		if (outData[outSize - 2] == 0x6A && outData[outSize - 1] == 0x81)
			return LIBEMV_NOT_SUPPORTED;
		if (outData[outSize - 2] == 0x6A && outData[outSize - 1] == 0x82)
		{
			if (libemv_debug_enabled)
				libemv_printf("PSE not found\n");
		}

		// Only 90 00 is OK otherwise use list of aids
		if (outData[outSize - 2] == 0x90 && outData[outSize - 1] == 0x00)
		{
			unsigned char sfiOfPSE;
			char sfiExists;
			unsigned char recordNo;
			LIBEMV_SEL_APPLICATION_INFO standartCandidate;

			int parseShift_1;
			unsigned short parseTag_1;
			unsigned char* parseData_1;
			int parseSize_1;

			sfiExists = 0;
			memset(&standartCandidate, 0, sizeof(standartCandidate));

			// Parse 6F (FCI Template)
			parseShift_1 = libemv_parse_tlv(outData, outSize - 2, &parseTag_1, &parseData_1, &parseSize_1);
			if (!parseShift_1)
				return LIBEMV_UNKNOWN_ERROR;
			if (parseTag_1 != TAG_FCI_TEMPLATE)
				return LIBEMV_UNKNOWN_ERROR;

			// Parse 84 (DF Name), A5 (FCI Proprietary Template)
			while (1)
			{
				int parseShift_2;
				unsigned short parseTag_2;
				unsigned char* parseData_2;
				int parseSize_2;

				parseShift_2 = libemv_parse_tlv(parseData_1, parseSize_1, &parseTag_2, &parseData_2, &parseSize_2);
				if (!parseShift_2)
					break;

				if (parseTag_2 == TAG_FCI_PROP_TEMPLATE)
				{
					// Parse 88 (SFI of the Directory Elementary File)
					// And save others like 5F2D (Language Preference)
					while (1)
					{
						int parseShift_3;
						unsigned short parseTag_3;
						unsigned char* parseData_3;
						int parseSize_3;

						parseShift_3 = libemv_parse_tlv(parseData_2, parseSize_2, &parseTag_3, &parseData_3, &parseSize_3);
						if (!parseShift_3)
							break;

						// Check SFI tag
						if (parseTag_3 == TAG_SFI_OF_DEF)
						{
							if (parseSize_3 != 1)
								return LIBEMV_UNKNOWN_ERROR;
							sfiExists = 1;
							sfiOfPSE = *parseData_3;
						}

						// Tag 5F2D (Language Preference)
						if (parseTag_3 == TAG_LANGUAGE_PREFERENCE)
						{
							if (parseSize_3 <= 8)
								memcpy(standartCandidate.strLanguagePreference, parseData_3, parseSize_3);
						}

						// Tag 9F11 (Issuer Code Table Index)
						if (parseTag_3 == TAG_ISSUER_CODE_TABLE_INDEX)
						{
							if (parseSize_3 == 1)
								standartCandidate.issuerCodeTableIndex = *parseData_3;
						}

						// Next
						parseData_2 += parseShift_3;
						parseSize_2 -= parseShift_3;
					}
				}

				// Next
				parseData_1 += parseShift_2;
				parseSize_1 -= parseShift_2;
			}

			// SFI must exist
			if (!sfiExists)
				return LIBEMV_UNKNOWN_ERROR;

			// Read record, start from record 1
			recordNo = 1;
			if (libemv_debug_enabled)
				libemv_printf("Try to read record with SFI: %02X\n", sfiOfPSE & 0xFF);

			sfiOfPSE <<= 3;
			sfiOfPSE |= 4;
			while (1)
			{
				int parseShift_4;
				unsigned short parseTag_4;
				unsigned char* parseData_4;
				int parseSize_4;

				if (!libemv_apdu(0x00, 0xB2, recordNo, sfiOfPSE, 0, "", &outSize, outData))
					return LIBEMV_ERROR_TRANSMIT;
				if (outData[outSize - 2] == 0x6A && outData[outSize - 1] == 0x81)
					return LIBEMV_NOT_SUPPORTED;
				// 6A 83 is the end
				if (outData[outSize - 2] != 0x90 || outData[outSize - 1] != 0x00)
					break;

				// Parse 70
				parseShift_4 = libemv_parse_tlv(outData, outSize - 2, &parseTag_4, &parseData_4, &parseSize_4);
				if (!parseShift_4)
					return LIBEMV_UNKNOWN_ERROR;
				if (parseTag_4 != 0x70)
					return LIBEMV_UNKNOWN_ERROR;

				// Parse every tag 61
				while (1)
				{
					int parseShift_5;
					unsigned short parseTag_5;
					unsigned char* parseData_5;
					int parseSize_5;
					LIBEMV_SEL_APPLICATION_INFO currentApplicationInfo;

					parseShift_5 = libemv_parse_tlv(parseData_4, parseSize_4, &parseTag_5, &parseData_5, &parseSize_5);
					if (!parseShift_5)
						break;

					// Tag must be only 61
					if (parseTag_5 != TAG_APPLICATION_TEMPLATE)
						break;

					// Parse applications info, 4F (ADF Name), 50 (Application Label), etc
					memcpy(&currentApplicationInfo, &standartCandidate, sizeof(LIBEMV_SEL_APPLICATION_INFO));
					while (1)
					{
						int parseShift_6;
						unsigned short parseTag_6;
						unsigned char* parseData_6;
						int parseSize_6;

						parseShift_6 = libemv_parse_tlv(parseData_5, parseSize_5, &parseTag_6, &parseData_6, &parseSize_6);
						if (!parseShift_6)
							break;

						// Tag 4F (ADF Name)
						if (parseTag_6 == TAG_ADF_NAME)
						{
							if (parseSize_6 <= 16)
							{
								currentApplicationInfo.DFNameLength = parseSize_6;
								memcpy(currentApplicationInfo.DFName, parseData_6, parseSize_6);
							}
						}

						// Tag 50 (Application Label)
						if (parseTag_6 == TAG_APPLICATION_LABEL)
						{
							if (parseSize_6 <= 16)
								memcpy(currentApplicationInfo.strApplicationLabel, parseData_6, parseSize_6);
						}

						// Tag 9F12 (Application Preferred Name)
						if (parseTag_6 == TAG_APP_PREFERRED_NAME)
						{
							if (parseSize_6 <= 16)
								memcpy(currentApplicationInfo.strApplicationPreferredName, parseData_6, parseSize_6);
						}

						// Tag 87 (Application Priority Indicator)
						if (parseTag_6 == TAG_APP_PRIORITY_INDICATOR)
						{
							if (parseSize_6 == 1)
							{
								if (*parseData_6 & 0x80)
									currentApplicationInfo.needCardholderConfirm = 1;
								currentApplicationInfo.priority = *parseData_6 & 0x0F;
							}
						}

						// Next
						parseData_5 += parseShift_6;
						parseSize_5 -= parseShift_6;
					}

					// Check currentApplicationInfo is candidate and then add to list
					if (candidateApplicationCount < MAX_CANDIDATE_APPLICATIONS && currentApplicationInfo.DFNameLength > 0
						&& check_candidate_in_app_list(&currentApplicationInfo))
					{
						if (libemv_debug_enabled)
							libemv_printf("Add candidate from PSE: %s\n", currentApplicationInfo.strApplicationLabel);
						memcpy(candidateApplications + candidateApplicationCount, &currentApplicationInfo, sizeof(LIBEMV_SEL_APPLICATION_INFO));
						candidateApplicationCount++;
					}

					// Next
					parseData_4 += parseShift_5;
					parseSize_4 -= parseShift_5;
				}

				// Next record number
				recordNo++;
			}
		}
	}

	// If no candidates found using PSE, build candidates using list of AIDs
	if (candidateApplicationCount == 0)
	{
		int i;
		for (i = 0; i < libemv_applications_count; i++)
		{
			int j;
			for (j = 0; j < libemv_applications[i].aidsCount; j++)
			{
				unsigned char selectionIndicator;
				selectionIndicator = 0;

				// For repeat select for 1 AID
				while (1)
				{
					int outSize;
					unsigned char outData[256];
					int selectAdfParse;
					LIBEMV_SEL_APPLICATION_INFO currentApplicationInfo;

					// SELECT AID in terminal list
					if (libemv_debug_enabled)
						libemv_printf("SELECT AID[%d][%d]\n", i, j);
					if (!libemv_apdu(0x00, 0xA4, 0x04, selectionIndicator, libemv_applications[i].aids[j].aidLength,
									libemv_applications[i].aids[j].aid, &outSize, outData))
						return LIBEMV_ERROR_TRANSMIT;
					if (outData[outSize - 2] == 0x6A && outData[outSize - 1] == 0x81)
						return LIBEMV_NOT_SUPPORTED;

					if (selectionIndicator == 0)
					{
						// Skip status codes except 90 00 or 62 83 (blocked)
						if (!(outData[outSize - 2] == 0x90 && outData[outSize - 1] == 0x00)
							&& !(outData[outSize - 2] == 0x62 && outData[outSize - 1] == 0x83))
							break;
					} else
					{
						// Skip status codes except 90 00, 62 xx, 63 xx
						if (!(outData[outSize - 2] == 0x90 && outData[outSize - 1] == 0x00)
							&& !(outData[outSize - 2] == 0x62) && !(outData[outSize - 2] == 0x63))
							break;
					}

					selectAdfParse = select_adf_parse(outData, outSize, &currentApplicationInfo);
					if (selectAdfParse != LIBEMV_OK)
						return selectAdfParse;

					// DF name must exists
					if (currentApplicationInfo.DFNameLength == 0)
						break;

					// Detect match exact
					if (libemv_applications[i].aids[j].aidLength == currentApplicationInfo.DFNameLength
						&& memcmp(libemv_applications[i].aids[j].aid, currentApplicationInfo.DFName, currentApplicationInfo.DFNameLength) == 0)
					{
						// Check currentApplicationInfo is candidate and then add to list
						if (candidateApplicationCount < MAX_CANDIDATE_APPLICATIONS && outData[outSize - 2] == 0x90 && outData[outSize - 1] == 0x00)
						{
							if (libemv_debug_enabled)
								libemv_printf("Add candidate from list AIDs, match exact: %s\n", currentApplicationInfo.strApplicationLabel);
							currentApplicationInfo.indexRID = i;
							memcpy(candidateApplications + candidateApplicationCount, &currentApplicationInfo, sizeof(LIBEMV_SEL_APPLICATION_INFO));
							candidateApplicationCount++;
						}
					}

					// Partial selection
					if (libemv_settings.appSelectionPartial && libemv_applications[i].aids[j].applicationSelectionIndicator
						&& libemv_applications[i].aids[j].aidLength < currentApplicationInfo.DFNameLength
						&& memcmp(libemv_applications[i].aids[j].aid, currentApplicationInfo.DFName, libemv_applications[i].aids[j].aidLength) == 0)
					{
						// Check currentApplicationInfo is candidate and then add to list
						if (candidateApplicationCount < MAX_CANDIDATE_APPLICATIONS && outData[outSize - 2] == 0x90 && outData[outSize - 1] == 0x00)
						{
							if (libemv_debug_enabled)
								libemv_printf("Add candidate from list AIDs, partial: %s\n", currentApplicationInfo.strApplicationLabel);
							currentApplicationInfo.indexRID = i;
							memcpy(candidateApplications + candidateApplicationCount, &currentApplicationInfo, sizeof(LIBEMV_SEL_APPLICATION_INFO));
							candidateApplicationCount++;
						}

						// Next selection with current aid
						selectionIndicator = 2;
						continue;
					}

					// Always break
					break;
				}
			}
		}
	}

	return LIBEMV_OK;
}

static char check_candidate_in_app_list(LIBEMV_SEL_APPLICATION_INFO* candidate)
{
	int i;
	for (i = 0; i < libemv_applications_count; i++)
	{
		int j;
		for (j = 0; j < libemv_applications[i].aidsCount; j++)
		{
			int smallSize;
			// Detect smaller size AID (from terminal) or DF name (from ICC)
			smallSize = libemv_applications[i].aids[j].aidLength;
			if (smallSize > candidate->DFNameLength)
				smallSize = candidate->DFNameLength;
			if (memcmp(libemv_applications[i].aids[j].aid, candidate->DFName, smallSize) == 0)
			{
				// Check exact match
				if (libemv_applications[i].aids[j].aidLength == candidate->DFNameLength)
				{
					candidate->indexRID = i;
					return 1;
				}
				// Check ASI
				if (libemv_settings.appSelectionPartial && libemv_applications[i].aids[j].applicationSelectionIndicator
					&& libemv_applications[i].aids[j].aidLength < candidate->DFNameLength)
				{
					candidate->indexRID = i;
					return 1;
				}
			}
		}
	}
	return 0;
}

static int select_adf_parse(unsigned char* rApdu, int rApduSize, LIBEMV_SEL_APPLICATION_INFO* appInfo)
{
	int parseShift_1;
	unsigned short parseTag_1;
	unsigned char* parseData_1;
	int parseSize_1;

	if (appInfo)
		memset(appInfo, 0, sizeof(LIBEMV_SEL_APPLICATION_INFO));

	// Parse 6F (FCI Template)
	parseShift_1 = libemv_parse_tlv(rApdu, rApduSize - 2, &parseTag_1, &parseData_1, &parseSize_1);
	if (!parseShift_1)
		return LIBEMV_UNKNOWN_ERROR;
	if (parseTag_1 != 0x6F)
		return LIBEMV_UNKNOWN_ERROR;

	// Parse 84 (DF Name), A5 (FCI Proprietary Template)
	while (1)
	{
		int parseShift_2;
		unsigned short parseTag_2;
		unsigned char* parseData_2;
		int parseSize_2;

		parseShift_2 = libemv_parse_tlv(parseData_1, parseSize_1, &parseTag_2, &parseData_2, &parseSize_2);
		if (!parseShift_2)
			break;

		// Tag 84 (DF Name)
		if (parseTag_2 == TAG_DF_NAME)
		{
			if (parseSize_2 <= 16)
			{
				if (appInfo)
				{
					memcpy(appInfo->DFName, parseData_2, parseSize_2);
					appInfo->DFNameLength = parseSize_2;
				}
			}
		}

		if (parseTag_2 == TAG_FCI_PROP_TEMPLATE)
		{
			// Parse all like 50 (Application Label) etc
			while (1)
			{
				int parseShift_3;
				unsigned short parseTag_3;
				unsigned char* parseData_3;
				int parseSize_3;

				parseShift_3 = libemv_parse_tlv(parseData_2, parseSize_2, &parseTag_3, &parseData_3, &parseSize_3);
				if (!parseShift_3)
					break;

				// Tag 50 (Application Label)
				if (parseTag_3 == TAG_APPLICATION_LABEL)
				{
					if (parseSize_3 <= 16)
					{
						if (appInfo)
							memcpy(appInfo->strApplicationLabel, parseData_3, parseSize_3);
					}
				}

				// Tag 87 (Application Priority Indicator)
				if (parseTag_3 == TAG_APP_PRIORITY_INDICATOR)
				{
					if (parseSize_3 == 1)
					{
						if (appInfo)
						{
							if (*parseData_3 & 0x80)
								appInfo->needCardholderConfirm = 1;
							appInfo->priority = *parseData_3 & 0x0F;
						}
					}
				}

				// Tag 9F38 (PDOL)
				if (parseTag_3 == TAG_PDOL)
				{
				}

				// Tag 5F2D (Language Preference)
				if (parseTag_3 == TAG_LANGUAGE_PREFERENCE)
				{
					if (parseSize_3 <= 8)
					{
						if (appInfo)
							memcpy(appInfo->strLanguagePreference, parseData_3, parseSize_3);
					}
				}

				// Tag 9F11 (Issuer Code Table Index)
				if (parseTag_3 == TAG_ISSUER_CODE_TABLE_INDEX)
				{
					if (parseSize_3 == 1)
					{
						if (appInfo)
							appInfo->issuerCodeTableIndex = *parseData_3;
					}
				}

				// Tag 9F12 (Application Preferred Name)
				if (parseTag_3 == TAG_APP_PREFERRED_NAME)
				{
					if (parseSize_3 <= 16)
					{
						if (appInfo)
							memcpy(appInfo->strApplicationPreferredName, parseData_3, parseSize_3);
					}
				}

				// Next
				parseData_2 += parseShift_3;
				parseSize_2 -= parseShift_3;
			}
		}

		// Next
		parseData_1 += parseShift_2;
		parseSize_1 -= parseShift_2;
	}

	return LIBEMV_OK;
}

static void zeroizeAppBuffer(void)
{
	int outSize;

	libemv_clear_tlv_buffer();

	// Add default value
	libemv_set_tag(TAG_TVR, "\x00\x00\x00\x00\x00", 5);
	libemv_set_tag(TAG_TSI, "\x00\x00", 2);
	libemv_set_tag(TAG_AIP, "\x00\x00", 2);

	// Add value from config
	libemv_set_tag(TAG_IFD_SERIAL_NUMBER, libemv_global.strIFDSerialNumber, strlen(libemv_global.strIFDSerialNumber));
	libemv_set_tag(TAG_TERMINAL_COUNTRY_CODE, libemv_global.terminalCountryCode, 2);
	libemv_set_tag(TAG_TERMINAL_CAPABILITIES, libemv_global.terminalCapabilities, 3);
	libemv_set_tag(TAG_ADDI_TERMINAL_CAPABILITIES, libemv_global.additionalTerminalCapabilities, 5);
	libemv_set_tag(TAG_TERMINAL_TYPE, &libemv_global.terminalType, 1);

	// Update pointers to data in app buffer
	libemv_TVR = (EMV_BITS*) libemv_get_tag(TAG_TVR, &outSize);
	libemv_TSI = (EMV_BITS*) libemv_get_tag(TAG_TSI, &outSize);
	libemv_capa = (EMV_BITS*) libemv_get_tag(TAG_TERMINAL_CAPABILITIES, &outSize);
	libemv_addi_capa = (EMV_BITS*) libemv_get_tag(TAG_ADDI_TERMINAL_CAPABILITIES, &outSize);
	libemv_AIP = (EMV_BITS*) libemv_get_tag(TAG_AIP, &outSize);
}

LIBEMV_API int libemv_application_selection(void)
{
	// No candidates
	if (candidateApplicationCount <= 0)
		return LIBEMV_TERMINATED;

	// Only one supported application
	if (candidateApplicationCount == 1)
	{
		if (candidateApplications[0].needCardholderConfirm)
		{
			if (libemv_debug_enabled)
				libemv_printf("Application need to be confirmed\n");
			if (libemv_settings.appSelectionSupportConfirm)
				return LIBEMV_NEED_CONFIRM_APPLICATION;
			else
				return LIBEMV_TERMINATED;
		} else
		{
			if (libemv_debug_enabled)
				libemv_printf("Select one application automatically\n");
			return libemv_select_application(0);
		}
	}

	// Multi application
	if (libemv_settings.appSelectionSupport)
	{
		if (libemv_debug_enabled)
			libemv_printf("User must select application\n");
		return LIBEMV_NEED_SELECT_APPLICATION;
	}

	// Application selection doesn't supported, select auto
	if (libemv_debug_enabled)
		libemv_printf("Select multi applications automatically\n");
	while (1)
	{
		int idx;
		int highestPriority, indexFound;
		int oldApplicationCount;
		int resultSelect;
		highestPriority = 16;
		indexFound = -1;
		oldApplicationCount = candidateApplicationCount;

		for (idx = 0; idx < candidateApplicationCount; idx++)
		{
			if (!candidateApplications[idx].needCardholderConfirm && candidateApplications[idx].priority < highestPriority)
			{
				// Skip priority is empty
				if (candidateApplications[idx].priority == 0 && highestPriority != 16)
					continue;
				highestPriority = candidateApplications[idx].priority;
				indexFound = idx;
			}
		}

		if (indexFound == -1)
			return LIBEMV_TERMINATED;

		if (libemv_debug_enabled)
			libemv_printf("The highest priority is: %d\n", highestPriority);

		resultSelect = libemv_select_application(indexFound);
		if (resultSelect == LIBEMV_OK)
			return resultSelect;
		else if (candidateApplicationCount < oldApplicationCount)
			continue;
		else
			return resultSelect;
	}

	return LIBEMV_UNKNOWN_ERROR;
}

LIBEMV_API int libemv_select_application(int indexApplication)
{
	int outSize;
	unsigned char outData[256];

	// Input parameter wrong
	if (indexApplication < 0 || indexApplication >= candidateApplicationCount)
		return LIBEMV_UNKNOWN_ERROR;

	// SELECT AID in terminal list
	if (libemv_debug_enabled)
		libemv_printf("SELECT application index: %d\n", indexApplication);
	if (!libemv_apdu(0x00, 0xA4, 0x04, 0x00, candidateApplications[indexApplication].DFNameLength,
		candidateApplications[indexApplication].DFName, &outSize, outData))
		return LIBEMV_ERROR_TRANSMIT;

	// Check if any error
	if (outData[outSize - 2] != 0x90 || outData[outSize - 1] != 0x00)
	{
		// Remove candidate from list
		if (libemv_debug_enabled)
			libemv_printf("Remove candidate from list\n");
		memmove(candidateApplications + indexApplication,
				candidateApplications + (indexApplication + 1),
				(candidateApplicationCount - indexApplication - 1) * sizeof(LIBEMV_SEL_APPLICATION_INFO));
		candidateApplicationCount--;
		return LIBEMV_UNKNOWN_ERROR;
	}

	// Store AID
	libemv_set_tag(TAG_AID, candidateApplications[indexApplication].DFName, candidateApplications[indexApplication].DFNameLength);

	// Extract tag to global buffer
	do
	{
		int parseShift_1;
		unsigned short parseTag_1;
		unsigned char* parseData_1;
		int parseSize_1;

		// Parse 6F (FCI Template)
		parseShift_1 = libemv_parse_tlv(outData, outSize - 2, &parseTag_1, &parseData_1, &parseSize_1);
		if (!parseShift_1)
			break;
		if (parseTag_1 != 0x6F)
			break;

		// Parse 84 (DF Name), A5 (FCI Proprietary Template)
		while (1)
		{
			int parseShift_2;
			unsigned short parseTag_2;
			unsigned char* parseData_2;
			int parseSize_2;

			parseShift_2 = libemv_parse_tlv(parseData_1, parseSize_1, &parseTag_2, &parseData_2, &parseSize_2);
			if (!parseShift_2)
				break;

			if (parseTag_2 == TAG_FCI_PROP_TEMPLATE)
			{
				// Parse all like 50 (Application Label) etc
				while (1)
				{
					int parseShift_3;
					unsigned short parseTag_3;
					unsigned char* parseData_3;
					int parseSize_3;

					parseShift_3 = libemv_parse_tlv(parseData_2, parseSize_2, &parseTag_3, &parseData_3, &parseSize_3);
					if (!parseShift_3)
						break;

					if (libemv_debug_enabled)
					{
						libemv_printf("Tag %4X: ", parseTag_3);
						libemv_debug_buffer("", parseData_3, parseSize_3, "\n");
					}
					libemv_set_tag(parseTag_3, parseData_3, parseSize_3);

					// Next
					parseData_2 += parseShift_3;
					parseSize_2 -= parseShift_3;
				}
			} else
			{
				if (libemv_debug_enabled)
				{
					libemv_printf("Tag %4X: ", parseTag_2);
					libemv_debug_buffer("", parseData_2, parseSize_2, "\n");
				}
				libemv_set_tag(parseTag_2, parseData_2, parseSize_2);
			}

			// Next
			parseData_1 += parseShift_2;
			parseSize_1 -= parseShift_2;
		}
	} while (0);

	// Store tags from LIBEMV_APPLICATIONS* libemv_applications
	{
		int indexRID;
		LIBEMV_APPLICATIONS* app;
		indexRID = candidateApplications[indexApplication].indexRID;
		app = &libemv_applications[indexRID];
		libemv_set_tag(TAG_ACQUIRER_ID, app->strAcquirerIdentifier, strlen(app->strAcquirerIdentifier));
		libemv_set_tag(TAG_APPLICATION_VERSION_NUMBER, app->applicationVersionNumber, 2);
		libemv_set_tag(TAG_MCC, app->merchantCategoryCode, 2);
		libemv_set_tag(TAG_MERCHANT_ID, app->strMerchantIdentifier, strlen(app->strMerchantIdentifier));
		libemv_set_tag(TAG_MERCHANT_NAME_AND_LOCATION, app->strMerchantNameAndLocation, strlen(app->strMerchantNameAndLocation));
		libemv_set_tag(TAG_TERMINAL_FLOOR_LIMIT, app->terminalFloorLimit, 4);
		libemv_set_tag(TAG_MERCHANT_NAME_AND_LOCATION, app->strTerminalIdentification, strlen(app->strTerminalIdentification));
		libemv_set_tag(TAG_RISK_MANAGEMENT_DATA, app->terminalRiskManagementData, app->terminalRiskManagementDataSize);
		libemv_set_tag(TAG_TRANSACTION_REFERENCE_CURRENCY, app->transactionReferenceCurrency, 2);
		libemv_set_tag(TAG_TRANSACTION_REFERENCE_EXPONENT, &app->transactionReferenceCurrencyExponent, 1);
	}

	indexApplicationSelected = indexApplication;
	return LIBEMV_OK;
}

LIBEMV_API int libemv_count_candidates(void)
{
	return candidateApplicationCount;
}

LIBEMV_API LIBEMV_SEL_APPLICATION_INFO* libemv_get_candidate(int indexApplication)
{
	// Input parameter wrong
	if (indexApplication < 0 || indexApplication >= candidateApplicationCount)
		return &candidateApplications[0];

	return &candidateApplications[indexApplication];
}

LIBEMV_API int libemv_get_processing_option(void)
{
	unsigned char* pdolTagValue;
	int pdolTagSize;
	unsigned char dolComposed[256];
	int dolComposedSize;
	unsigned char lcData[256];
	int lcSize;
	int outSize;
	unsigned char outData[256];
	int processingOptionResult;

	processingOptionResult = LIBEMV_UNKNOWN_ERROR;
	dolComposedSize = 0;
	lcSize = 0;
	if (libemv_debug_enabled)
		libemv_printf("Get processing option\n");

	pdolTagValue = libemv_get_tag(TAG_PDOL, &pdolTagSize);
	if (pdolTagValue)
	{
		dolComposedSize = libemv_dol(pdolTagValue, pdolTagSize, dolComposed);
		if (dolComposedSize > 0)
		{
			lcSize = libemv_make_tlv(dolComposed, dolComposedSize, TAG_COMMAND_TEMPLATE, lcData);
		}
	} else
	{
		if (libemv_debug_enabled)
			libemv_printf("PDOL is absent\n");
		lcSize = 2;
		lcData[0] = 0x83;
		lcData[1] = 0x00;
	}

	do
	{
		int parseShift_1;
		unsigned short parseTag_1;
		unsigned char* parseData_1;
		int parseSize_1;

		if (!libemv_apdu(0x80, 0xA8, 0x00, 0x00, lcSize, lcData, &outSize, outData))
		{
			processingOptionResult = LIBEMV_ERROR_TRANSMIT;
			break;
		}
		if (outData[outSize - 2] == 0x69 && outData[outSize - 1] == 0x85)
		{
			processingOptionResult = LIBEMV_NOT_SATISFIED;
			break;
		}
		if (outData[outSize - 2] != 0x90 || outData[outSize - 1] != 0x00)
		{
			processingOptionResult = LIBEMV_UNKNOWN_ERROR;
			break;
		}

		// Parse 6F (FCI Template)
		parseShift_1 = libemv_parse_tlv(outData, outSize - 2, &parseTag_1, &parseData_1, &parseSize_1);
		if (!parseShift_1)
		{
			processingOptionResult = LIBEMV_UNKNOWN_ERROR;
			break;
		}

		// Format 1
		if (parseTag_1 == TAG_RESPONSE_FORMAT_1)
		{
			if (parseSize_1 < 6 || (parseSize_1 - 2) % 4 != 0)
			{
				processingOptionResult = LIBEMV_UNKNOWN_ERROR;
				break;
			}
			// [2 bytes AIP][N bytes AFL]
			libemv_set_tag(TAG_AIP, parseData_1, 2);
			libemv_set_tag(TAG_AFL, parseData_1 + 2, parseSize_1 - 2);

			if (libemv_debug_enabled)
				libemv_debug_buffer("AIP: ", parseData_1, 2, "\n");
			if (libemv_debug_enabled)
				libemv_debug_buffer("AFL: ", parseData_1 + 2, parseSize_1 - 2, "\n");

			processingOptionResult = LIBEMV_OK;
			break;
		}

		// Format 2
		if (parseTag_1 == TAG_RESPONSE_FORMAT_2)
		{
			int tagSize;
			unsigned char* tagValue;
			char aipExist;
			aipExist = 0;

			// Parse AIP, AFL
			while (1)
			{
				int parseShift_2;
				unsigned short parseTag_2;
				unsigned char* parseData_2;
				int parseSize_2;

				parseShift_2 = libemv_parse_tlv(parseData_1, parseSize_1, &parseTag_2, &parseData_2, &parseSize_2);
				if (!parseShift_2)
					break;

				if (parseTag_2 == TAG_AIP)
				{
					if (parseSize_2 != 2)
						break;
					aipExist = 1;
				}

				libemv_set_tag(parseTag_2, parseData_2, parseSize_2);

				// Next
				parseData_1 += parseShift_2;
				parseSize_1 -= parseShift_2;
			}

			tagValue = libemv_get_tag(TAG_AIP, &tagSize);
			if (!aipExist)
			{
				processingOptionResult = LIBEMV_UNKNOWN_ERROR;
				break;
			}
			if (libemv_debug_enabled)
				libemv_debug_buffer("AIP: ", tagValue, tagSize, "\n");

			tagValue = libemv_get_tag(TAG_AFL, &tagSize);
			if (!tagValue || tagSize % 4 != 0)
			{
				processingOptionResult = LIBEMV_UNKNOWN_ERROR;
				break;
			}
			if (libemv_debug_enabled)
				libemv_debug_buffer("AFL: ", tagValue, tagSize, "\n");

			processingOptionResult = LIBEMV_OK;
			break;
		}

		// Tag unknown
		processingOptionResult = LIBEMV_UNKNOWN_ERROR;
		break;
	} while (0);

	if (processingOptionResult != LIBEMV_OK)
	{
		// Remove candidate from list
		if (libemv_debug_enabled)
			libemv_printf("Remove candidate from list\n");
		memmove(candidateApplications + indexApplicationSelected,
			candidateApplications + (indexApplicationSelected + 1),
			(candidateApplicationCount - indexApplicationSelected - 1) * sizeof(LIBEMV_SEL_APPLICATION_INFO));
		candidateApplicationCount--;
	}
	return processingOptionResult;
}

LIBEMV_API int libemv_read_app_data(void)
{
	unsigned char* aflValue;
	int aflSize;
	unsigned char* aflCurrent;
	int aflIndex, i;
	int tagSize;

	if (libemv_debug_enabled)
		libemv_printf("Read application data\n");

	//start static data authentication again
	static_data_to_be_auth_len = 0;

	aflValue = libemv_get_tag(TAG_AFL, &aflSize);
	if (!aflValue || (aflSize % 4) != 0)
		return LIBEMV_UNKNOWN_ERROR;

	aflCurrent = aflValue;
	for (aflIndex = 0; aflIndex < aflSize; aflIndex += 4, aflCurrent += 4)
	{
		unsigned char record;
		unsigned char p2;
		p2 = (aflCurrent[0] & 0xF8) | 0x04;
		if (aflCurrent[1] > aflCurrent[2])
			return LIBEMV_UNKNOWN_ERROR;
		for (record = aflCurrent[1]; record <= aflCurrent[2]; record++)
		{
			int outSize;
			unsigned char outData[256];
			int parseShift_1;
			unsigned short parseTag_1;
			unsigned char* parseData_1;
			int parseSize_1;

			// READ RECORD
			if (libemv_debug_enabled)
				libemv_printf("READ RECORD, SFI: %d, record number: %d\n", (aflCurrent[0] & 0xF8) >> 3, record);
			if (!libemv_apdu(0x00, 0xB2, record, p2, 0, "", &outSize, outData))
				return LIBEMV_ERROR_TRANSMIT;

			if (outData[outSize - 2] != 0x90 || outData[outSize - 1] != 0x00)
				return LIBEMV_TERMINATED;

			//include this record in the secure data field?
			if(aflCurrent[3] != 0)
			{
				if((aflCurrent[0] >> 3) < 10)
				{
					//TLV must be a template tag
					if(outData[0] != 0x70)
						return LIBEMV_UNKNOWN_ERROR;

					for(i = 0; i < outData[1]; i++)
						static_data_to_be_auth[static_data_to_be_auth_len++] = outData[2+i];
				}
				else
				{
					for(i = 0; i < outSize; i++)
						static_data_to_be_auth[static_data_to_be_auth_len++] = outData[i];
				}
			}

			// Parse 70
			parseShift_1 = libemv_parse_tlv(outData, outSize - 2, &parseTag_1, &parseData_1, &parseSize_1);
			if (!parseShift_1)
				return LIBEMV_UNKNOWN_ERROR;
			if (parseTag_1 != TAG_READ_RECORD_RESPONSE_TEMPLATE)
				return LIBEMV_UNKNOWN_ERROR;

			// Parse data in records
			while (1)
			{
				int parseShift_2;
				unsigned short parseTag_2;
				unsigned char* parseData_2;
				int parseSize_2;

				parseShift_2 = libemv_parse_tlv(parseData_1, parseSize_1, &parseTag_2, &parseData_2, &parseSize_2);
				if (!parseShift_2)
					break;

				if (libemv_debug_enabled)
				{
					libemv_printf("Tag %4X: ", parseTag_2);
					libemv_debug_buffer("", parseData_2, parseSize_2, "\n");
				}
				libemv_set_tag(parseTag_2, parseData_2, parseSize_2);

				// Next
				parseData_1 += parseShift_2;
				parseSize_1 -= parseShift_2;
			}
		}
	}

	// Check for mandatory
	if (!libemv_get_tag(TAG_APPLICATION_EXP_DATE, &tagSize) || !libemv_get_tag(TAG_PAN, &tagSize)
		|| !libemv_get_tag(TAG_CDOL_1, &tagSize) || !libemv_get_tag(TAG_CDOL_2, &tagSize))
		return LIBEMV_TERMINATED;

	return LIBEMV_OK;
}

LIBEMV_API int libemv_authenticate_card(void)
{
	unsigned char *tag_data;
	int size;

	tag_data = libemv_get_tag(TAG_AIP, &size);
	if(tag_data[0] & 0x20)
		return verify_dda();
	else
		return verify_sda();
}

LIBEMV_API int libemv_process_transaction(void)
{
	unsigned char cmd_data[1024], read_data[1024], tag[6];
	unsigned char *cdol1, *ac;
	unsigned short ac_tag;
	int i, cmd_size = 0, read_size, ac_size, cdol1_size;

	//authorize amount
	tobcd(9543, tag, 6);
	tag[0] = 0x00; tag[1] = 0x00; tag[2] = 0x00; tag[3] = 0x00; tag[4] = 0x10; tag[5] = 0x00;
	libemv_set_tag(0x9F02, tag, 6);

	//cashback amount
	tobcd(0, tag, 6);
	libemv_set_tag(0x9F03, tag, 6);

	//currency code
	tobcd(840, tag, 2);
	libemv_set_tag(0x5F2A, tag, 2);

	//currency code
	tobcd(840, tag, 2);
	libemv_set_tag(0x5F2A, tag, 2);

	//transaction type
	tobcd(0, tag, 2);
	libemv_set_tag(0x9C, tag, 2);

	//read the CDOL1, which tells us what to send for the generate ac command
	cdol1 = libemv_get_tag(TAG_CDOL_1, &cdol1_size);
	if(cdol1 == NULL)
		return LIBEMV_PROCESS_FAIL;

	//compute the CDOL1
	cmd_size = libemv_dol(cdol1, cdol1_size, cmd_data);
	if(cmd_size < 0)
		return LIBEMV_PROCESS_FAIL;

	libemv_apdu(0x80, 0xAE, 0x80, 0x00, cmd_size, cmd_data, &read_size, read_data);
	libemv_parse_tlv(read_data, read_size, &ac_tag, &ac, &ac_size);
	if(ac_tag != 0x80)
		return LIBEMV_PROCESS_FAIL;

	printf("AC: ");
	for(i = 0; i < ac_size; i++)
		printf("%02X ", ac[i]);
	printf("\n");

	

	return LIBEMV_OK;
}

static int verify_sda(void)
{
	unsigned char key[256];
	int ret, key_size;

	if(ret = read_issuer_public_key(key, &key_size))
		return ret;

	return LIBEMV_OK;
}

static int verify_dda(void)
{
	unsigned char key[256], read_data[256], cmd_data[1024], tag[8], cert[256], mlist[1024], strdate[6];
	int ret, key_size, asn_size, ddol_size, cmd_size, read_size, size, i, ldd;
	unsigned char *ddol, *asn, *tag_data, *ptr;
	unsigned short asn_tag;
	NN_DIGIT s[MAX_NN_DIGITS], es[MAX_NN_DIGITS], ns[MAX_NN_DIGITS], x[MAX_NN_DIGITS];
	unsigned char hash[20];
	SHA1Context sha1;

	if(ret = read_icc_public_key(key, &key_size))
		return ret;

	//compute some random data
	tag[0] = rand()%255; tag[1] = rand()%255; tag[2] = rand()%255; tag[3] = rand()%255;
	libemv_set_tag(0x9F37, tag, 4);

	//transaction number
	tobcd(transaction_number++, tag, 4);
	libemv_set_tag(0x9F41, tag, 4);

	//datetime
	libemv_get_date(strdate);
	tobcd(atoi(strdate), tag, 3);
	libemv_set_tag(0x9A, tag, 3);

	libemv_get_time(strdate);
	tobcd(atoi(strdate), tag, 3);
	libemv_set_tag(0x9F21, tag, 3);

	//read the DDOL, which tells us what to send for the initiate command
	ddol = libemv_get_tag(TAG_DDOL, &ddol_size);
	if(ddol == NULL)
		return LIBEMV_VERIFY_FAIL;

	//compute the ddol
	cmd_size = libemv_dol(ddol, ddol_size, cmd_data);

	//send the intitiate command
	libemv_apdu(0x00, 0x88, 0x00, 0x00, cmd_size, cmd_data, &read_size, read_data);
	libemv_parse_tlv(read_data, read_size, &asn_tag, &asn, &asn_size);
	if(asn_tag != 0x80)
		return LIBEMV_VERIFY_FAIL;
	if(asn_size != key_size)
		return LIBEMV_VERIFY_FAIL;

	//get the exponent
	tag_data = libemv_get_tag(TAG_ISSUER_PUBLIC_KEY_EXPONENT, &size);

	NN_Decode(s, MAX_NN_DIGITS, asn, asn_size);
	NN_Decode(ns, MAX_NN_DIGITS, key, key_size);
	NN_Decode(es, MAX_NN_DIGITS, tag_data, size);
	//S^(eS)mod nS
	NN_AssignZero(x, MAX_NN_DIGITS);
	NN_ModExp(x, s, es, size, ns, key_size);
	NN_Encode(cert, key_size, x, key_size);

	// Step 2: The Recovered Data Trailer is equal to 'BC'
	if(cert[key_size - 1] != 0xBC)
		return LIBEMV_VERIFY_FAIL;

	// Step 3: The Recovered Data Header is equal to '6A'
	if(cert[0] != 0x6A)
		return LIBEMV_VERIFY_FAIL;

	// Step 4: The Certificate Format is equal to '05'
	if(cert[1] != 0x05)
		return LIBEMV_VERIFY_FAIL;

	// Step 5: Concatenation of cert data and the DDOL data
	ptr = mlist;
	for(i = 0; i < key_size - 22; i++) *ptr++ = cert[i+1];
	for(i = 0; i < cmd_size; i++) *ptr++ = cmd_data[i];

	// Step 6: Generate hash from concatenation
	SHA1Reset(&sha1);
	SHA1Input(&sha1, mlist, ptr - mlist);
	SHA1Result(&sha1);
	for(i = 0; i < 5; i++)
	{
		hash[(i*4)+0] = (sha1.Message_Digest[i] >> 24) & 0xFF;
		hash[(i*4)+1] = (sha1.Message_Digest[i] >> 16) & 0xFF;
		hash[(i*4)+2] = (sha1.Message_Digest[i] >> 8) & 0xFF;
		hash[(i*4)+3] = (sha1.Message_Digest[i] >> 0) & 0xFF;
	}

	// Step 7: Compare the hash result with the recovered hash result.
	//         They have to be equal 
	for(i = 0; i < 20; i++)
	{
		if(hash[i] != cert[key_size - 21 + i])
			return LIBEMV_VERIFY_FAIL;
	}
	
	//store the ICC Dynamic Number
	ldd = cert[3];
	libemv_set_tag(0x9F4C, &cert[4], ldd);

	return LIBEMV_OK;
}

static int read_issuer_public_key(unsigned char *key, int *key_size)
{
	int size, i, ret, iin_len, cert_len;
	unsigned char *enc_cert, *tag_data, *aid, *pub_key_index;
	unsigned char cert[256];
	NN_DIGIT s[MAX_NN_DIGITS], es[MAX_NN_DIGITS], ns[MAX_NN_DIGITS], x[MAX_NN_DIGITS];
	EMV_RID_MODULUS *pubkey = NULL;
	unsigned char mlist[1024], iin[12];
	unsigned char *ptr = mlist;
	unsigned char hash[20];
	SHA1Context sha1;

	//get the aid
	aid = libemv_get_tag(TAG_AID, &size);
	if(aid == NULL)
	{
		if(libemv_debug_enabled)
			libemv_printf("AID not found\n");
		return LIBEMV_VERIFY_FAIL;
	}

	//the first 5 bytes are the RID, we use that with the with the public key index to look up the modulus
	pub_key_index = libemv_get_tag(TAG_CERTIFICATE_AUTH_PKI, &size);
	if(pub_key_index == NULL)
	{
		if(libemv_debug_enabled)
			libemv_printf("Public key index not found\n");
		return LIBEMV_VERIFY_FAIL;
	}

	//find the public key for the RID/index
	for(i = 0; i < libemv_public_modulus_count; i++)
	{
		if(libemv_public_modulus[i].index == pub_key_index[0] &&
			libemv_public_modulus[i].rid[0] == aid[0] &&
			libemv_public_modulus[i].rid[1] == aid[1] &&
			libemv_public_modulus[i].rid[2] == aid[2] &&
			libemv_public_modulus[i].rid[3] == aid[3] &&
			libemv_public_modulus[i].rid[4] == aid[4])
		{
			pubkey = &libemv_public_modulus[i];
			cert_len = pubkey->modulus_len;
			break;
		}
	}

	if(pubkey == NULL)
	{
		if(libemv_debug_enabled)
			libemv_printf("Public modulus was not found for RID/index\n");
		return LIBEMV_VERIFY_FAIL;
	}

	//get the issuer certificate
	enc_cert = libemv_get_tag(TAG_ISSUER_PUBLIC_KEY_CERTIFICATE, &size);
	if(enc_cert == NULL)
	{
		if(libemv_debug_enabled)
			libemv_printf("Public certificate not found\n");
		return LIBEMV_VERIFY_FAIL;
	}

	if(size != cert_len)
	{
		if(libemv_debug_enabled)
			libemv_printf("Public modulus length did not match public modulus\n");
		return LIBEMV_VERIFY_FAIL;
	}

	NN_Decode(s, MAX_NN_DIGITS, enc_cert, cert_len);
	NN_Decode(ns, MAX_NN_DIGITS, pubkey->modulus, cert_len);
	NN_Decode(es, MAX_NN_DIGITS, pubkey->exponent, pubkey->exponent_len);

	//S^(eS)mod nS
	NN_AssignZero(x, MAX_NN_DIGITS);
	NN_ModExp(x, s, es, pubkey->exponent_len, ns, cert_len);
	NN_Encode(cert, cert_len, x, cert_len);

	// Step 2: The Recovered Data Trailer is equal to 'BC'
	if(cert[cert_len - 1] != 0xBC)
		return LIBEMV_VERIFY_FAIL;

	// Step 3: The Recovered Data Header is equal to '6A'
	if(cert[0] != 0x6A)
		return LIBEMV_VERIFY_FAIL;

	// Step 4: The Certificate Format is equal to '02'
	if(cert[1] != 0x02)
		return LIBEMV_VERIFY_FAIL;

	// Step 5: Concatenation of Certificate Format through Issuer Public Key
	//         or Leftmost Digits of the Issuer Public Key, 
	//         followed by the Issuer Public Key Remainder (if present),
	//         and the Issuer Public Key Exponent
	ptr = mlist;
	for(i = 1; i < 14 + (cert_len - 36) + 1; i++) *ptr++ = cert[i];
	tag_data = libemv_get_tag(TAG_ISSUER_PUBLIC_KEY_REMAINDER, &size);
	if(tag_data != NULL) { for(i = 0; i < size; i++) *ptr++ = tag_data[i]; }
	tag_data = libemv_get_tag(TAG_ISSUER_PUBLIC_KEY_EXPONENT, &size);
	if(tag_data != NULL) { for(i = 0; i < size; i++) *ptr++ = tag_data[i]; }

	// Step 6: Generate hash from concatenation
	SHA1Reset(&sha1);
	SHA1Input(&sha1, mlist, ptr - mlist);
	SHA1Result(&sha1);
	for(i = 0; i < 5; i++)
	{
		hash[(i*4)+0] = (sha1.Message_Digest[i] >> 24) & 0xFF;
		hash[(i*4)+1] = (sha1.Message_Digest[i] >> 16) & 0xFF;
		hash[(i*4)+2] = (sha1.Message_Digest[i] >> 8) & 0xFF;
		hash[(i*4)+3] = (sha1.Message_Digest[i] >> 0) & 0xFF;
	}

	// Step 7: Compare the hash result with the recovered hash result.
	//         They have to be equal 
	for(i = 0; i < 20; i++)
	{
		if(hash[i] != cert[i + 15 + (cert_len - 36)])
			return LIBEMV_VERIFY_FAIL;
	}

	// Step 8: Verify that the Issuer Identifier matches the lefmost 3-8 PAN digits
	iin_len = 4;
	while(cert[2 + iin_len - 1] == 0xFF)
		iin_len--;

	tag_data = libemv_get_tag(TAG_PAN, &size);
	if(tag_data == NULL || size < iin_len)
		return LIBEMV_VERIFY_FAIL;

	for(i = 0; i < iin_len; i++)
	{
		if(cert[2 + i] != tag_data[i])
			return LIBEMV_VERIFY_FAIL;
	}

	// Step 9: Verify that the last day of the month specified in the
	//         Certification Expiration Date is equal to or later than today's date.

	//copy the public key
	ptr = key;
	for(i = 15; i < 15 + (cert_len - 36); i++) *ptr++ = cert[i];
	//add the remainder
	tag_data = libemv_get_tag(TAG_ISSUER_PUBLIC_KEY_REMAINDER, &size);
	if(tag_data != NULL) { for(i = 0; i < size; i++) *ptr++ = tag_data[i]; }

	*key_size = ptr - key;
	return LIBEMV_OK;
}

static int read_icc_public_key(unsigned char *key, int *key_size)
{
	unsigned char issuer_key[256];
	unsigned char *enc_cert, *tag_data, *sdal_data;
	int i, j, ret, cert_size, size, es_size, sdal_size, iin_len;
	unsigned char cert[256];
	unsigned char mlist[1024], iin[12];
	unsigned char *ptr = mlist;
	NN_DIGIT s[MAX_NN_DIGITS], es[MAX_NN_DIGITS], ns[MAX_NN_DIGITS], x[MAX_NN_DIGITS];
	unsigned char hash[20];
	SHA1Context sha1;

	//read the issuer public key
	if(ret = read_issuer_public_key(issuer_key, &cert_size))
		return ret;
	NN_Decode(ns, MAX_NN_DIGITS, issuer_key, cert_size);

	//get the icc certificate
	enc_cert = libemv_get_tag(TAG_ICC_PUBLIC_KEY_CERTIFICATE, &size);
	if(enc_cert == NULL)
		return LIBEMV_VERIFY_FAIL;
	NN_Decode(s, MAX_NN_DIGITS, enc_cert, size);

	//get the exponent
	tag_data = libemv_get_tag(TAG_ISSUER_PUBLIC_KEY_EXPONENT, &es_size);
	if(tag_data == NULL)
		return LIBEMV_VERIFY_FAIL;
	NN_Decode(es, MAX_NN_DIGITS, tag_data, es_size);

	//S^(eS)mod nS
	NN_AssignZero(x, MAX_NN_DIGITS);
	NN_ModExp(x, s, es, es_size, ns, cert_size);
	NN_Encode(cert, cert_size, x, cert_size);

	// Step 2: The Recovered Data Trailer is equal to 'BC'
	if(cert[cert_size - 1] != 0xBC)
		return LIBEMV_VERIFY_FAIL;

	// Step 3: The Recovered Data Header is equal to '6A'
	if(cert[0] != 0x6A)
		return LIBEMV_VERIFY_FAIL;

	// Step 4: The Certificate Format is equal to '02'
	if(cert[1] != 0x04)
		return LIBEMV_VERIFY_FAIL;

	// Step 5: Concatenate for hash
	//	Certificate Format
	//	Application PAN
	//	Certificate Expiration Date
	//	Certificate Serial Number
	//	Hash Algorithm Indicator
	//	ICC Public Key Algorithm Indicator
	//	ICC Public Key Lnegth
	//	ICC Public Key Exponent Length
	//	ICC Public Key or Leftmost Digits of the ICC Public Key
	//	ICC Public Key Remainder (if present)
	//	ICC Public Key Exponent
	//	Data located by the AFL
	//	SDA Tag List
	ptr = mlist;
	for(i = 1; i < 1 + (cert_size - 22); i++) *ptr++ = cert[i];
	tag_data = libemv_get_tag(TAG_ICC_PUBLIC_KEY_REMAINDER, &size);
	if(tag_data != NULL) { for(i = 0; i < size; i++) *ptr++ = tag_data[i]; }
	tag_data = libemv_get_tag(TAG_ICC_PUBLIC_KEY_EXPONENT, &size);
	if(tag_data != NULL) { for(i = 0; i < size; i++) *ptr++ = tag_data[i]; }
	//add the sdal
	for(i = 0; i < static_data_to_be_auth_len; i++) *ptr++ = static_data_to_be_auth[i];
	//add the SDA tag list
	sdal_data = libemv_get_tag(TAG_SDA, &sdal_size);
	for(i = 0; i < sdal_size; i++)
	{
		tag_data = libemv_get_tag(sdal_data[i], &size);
		if(tag_data != NULL) { for(j = 0; j < size; j++) *ptr++ = tag_data[j]; }
	}

	// Step 6: Generate hash from concatenation
	SHA1Reset(&sha1);
	SHA1Input(&sha1, mlist, ptr - mlist);
	SHA1Result(&sha1);
	for(i = 0; i < 5; i++)
	{
		hash[(i*4)+0] = (sha1.Message_Digest[i] >> 24) & 0xFF;
		hash[(i*4)+1] = (sha1.Message_Digest[i] >> 16) & 0xFF;
		hash[(i*4)+2] = (sha1.Message_Digest[i] >> 8) & 0xFF;
		hash[(i*4)+3] = (sha1.Message_Digest[i] >> 0) & 0xFF;
	}

	// Step 7: Compare the hash result with the recovered hash result.
	//         They have to be equal 
	for(i = 0; i < 20; i++)
	{
		if(hash[i] != cert[cert_size - 21 + i])
			return LIBEMV_VERIFY_FAIL;
	}

	// Step 8: Verify that the Issuer Identifier matches the lefmost 3-8 PAN digits
	iin_len = 8;
	while(cert[2 + iin_len - 1] == 0xFF)
		iin_len--;

	tag_data = libemv_get_tag(TAG_PAN, &size);
	if(tag_data == NULL || size < iin_len)
		return LIBEMV_VERIFY_FAIL;

	for(i = 0; i < iin_len; i++)
	{
		if(cert[2 + i] != tag_data[i])
			return LIBEMV_VERIFY_FAIL;
	}

	// Step 9: Verify that the last day of the month specified 
	//         in the Certification Expiration Date is equal to or later than today's date. 
	
	//copy the public key
	ptr = key;
	for(i = 0; i < (cert_size - 42); i++) *ptr++ = cert[i+21];
	//add the remainder
	tag_data = libemv_get_tag(TAG_ICC_PUBLIC_KEY_REMAINDER, &size);
	if(tag_data != NULL) { for(i = 0; i < size; i++) *ptr++ = tag_data[i]; }

	*key_size = ptr - key;
	return LIBEMV_OK;
}
