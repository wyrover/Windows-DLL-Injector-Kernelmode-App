#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <sstream>
#include <Wininet.h>
#include <Iphlpapi.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string>
#include <time.h>
#include <Shlwapi.h>

#pragma comment ( lib, "Wininet.lib" )
#pragma comment ( lib, "Iphlpapi.lib" )
#pragma comment ( lib, "Shlwapi.lib" )

using namespace std;

#include "resource.h"

// User Information
string License;
string Name;

// Misc Functions.
string ToLowercase ( string Text )
{
	string newStr = "";

	for ( SIZE_T i = 0; i < Text.length (); i ++ )
	{
		if ( Text.at ( i ) >= 'A' &&
			 Text.at ( i ) <= 'Z' )
			newStr += Text.at ( i ) + 32;
		else
			newStr += Text.at ( i );
	}

	return newStr;
}
//

// Text Encryption/Decryption
string encryptText ( string regularText )
{
	string encryptedText;

	for ( SIZE_T i = 0; i < regularText.length (); i ++ )
		encryptedText += regularText.at ( i ) + 0x01;

	return encryptedText;
}
string decryptText ( string encryptedText )
{
	string decryptedText;

	for ( SIZE_T i = 0; i < encryptedText.length (); i ++ )
		decryptedText += encryptedText.at ( i ) - 0x01;

	return decryptedText;
}
//

string GetMac ()
{
    char data[4096];
    ZeroMemory( data, 4096 );
     unsigned long  len = 4000;
    PIP_ADAPTER_INFO pinfo = ( PIP_ADAPTER_INFO ) data;
    char sbuf[20];
    string sret;

    DWORD ret = GetAdaptersInfo( pinfo, &len );
    if( ret != ERROR_SUCCESS )
        return string("");

    for(int k = 0; k < 5; k++ ) {
        sprintf_s(sbuf,"%02X-",pinfo->Address[k]);
        sret += sbuf;
    }
    sprintf_s(sbuf,"%02X",pinfo->Address[5]);
    sret += sbuf;
	string trimDash;

	for ( SIZE_T i = 0; i < sret.length (); i ++ )
		if ( sret.at ( i ) != '-' )
			trimDash += sret.at ( i );

    return( trimDash );
}
//

string GetLicense ()
{
	// Encrypt
	string LicenseNum;
	string FinalNum;

	// System Information
	SYSTEM_INFO SI;
	GetSystemInfo ( &SI );

	// Convert HDD to string
	stringstream ss;
	ss << GetMac ();
	ss << (void*) SI.dwProcessorType;
	ss << SI.dwNumberOfProcessors;
	LicenseNum += ss.str ();

	// Encrypt
	for ( SIZE_T i = 0; i < LicenseNum.length (); i ++ )
	{		
		if ( ( LicenseNum.at ( i ) >= '0' ) &&
			 ( LicenseNum.at ( i ) <= '9' ) )
			FinalNum += (char) ( 65 + ( LicenseNum.at ( i ) - 48 ) );
		else
			FinalNum += (char) ( 48 + ( LicenseNum.at ( i ) - 65 ) );
	}

	return FinalNum;
}
//

BOOL CheckOnline ( string License )
{
	// Create the url equivelant
	string Url = decryptText ( "iuuq;00qspkfdusbjo/ofu0JokfdUPS0DifdlMjdfotf/qiq@mjdfotf>" );
	Url += License;

	// Delete cache
	DeleteUrlCacheEntry ( Url.c_str () );

	// Create the connection
	HINTERNET hInternet = InternetOpen ( NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL );
	HINTERNET hUrl      = InternetOpenUrlA ( hInternet, Url.c_str (), NULL, NULL, NULL, NULL );

	// Read
	char szBuffer [256];
	DWORD bytesRead;
	InternetReadFile ( hUrl, &szBuffer, 256, &bytesRead );

	// Close the connection
	InternetCloseHandle ( hInternet );
	InternetCloseHandle ( hUrl );

	// Decrypt the encrypted string
	string message;
	int Counter = 0;

	for ( SIZE_T i = 0; i < strlen ( szBuffer ); i ++ )
	{
		if ( (char) ( szBuffer [i] + 20 ) == '-' )
			++Counter;

		if ( Counter < 2 )
			message += (char) ( szBuffer [i] + 20 );
	}

	// Obtain information from message
	int dash = message.find_first_of ( "-" );

	License = message.substr ( 0, dash );
	Name = message.substr ( dash + 1, message.length () );

	if ( !strcmp ( ToLowercase ( License ).c_str (), ToLowercase ( GetLicense () ).c_str () ) )
		return TRUE;
	else
		return FALSE;
}
//