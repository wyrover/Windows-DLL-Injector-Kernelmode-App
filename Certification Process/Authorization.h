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

BOOL CheckOnline ( string UserLicense )
{
	return TRUE;
}
//