#include "Authorization.h"

// Structures
struct MODULE_INFO
{
	DWORD dwBaseAddr;
	DWORD dwSize;
};
//

// Main Thread
HANDLE hMain;

// Global Variables
string currentDir;
string dllName;
string processTarget;

// Scan variables
DWORD dwResults [999];
int   results;

// Debugging Function
template <class T> void la ( T Value )
{
	stringstream ss;
	ss << Value;
	string str;
	str += ss.str ();
	MessageBox ( 0, str.c_str (), 0, 0 );
}
//

// Scan memory locations
void ScanMemory ( DWORD dwStartAddr, DWORD dwEndAddr, VOID* Signature, SIZE_T szSig )
{
	results = 0;

	// Change this to dwStartAddr
	for ( dwStartAddr; dwStartAddr < dwEndAddr; dwStartAddr ++ )
	{
		MEMORY_BASIC_INFORMATION MBI;
		VirtualQuery ( (LPCVOID) dwStartAddr, &MBI, sizeof ( MEMORY_BASIC_INFORMATION ) );

		if ( MBI.State == MEM_COMMIT )
		{
			// End Address
			DWORD dwStopAddr = (DWORD) MBI.BaseAddress + (DWORD) MBI.RegionSize - 1 - szSig;

			for ( DWORD addr = (DWORD) MBI.BaseAddress; addr < dwStopAddr; addr ++ )
			{
				__try
				{
					// Check its signature
					if ( !memcmp ( (void*) addr, Signature, szSig ) )
					{
						dwResults [results] = addr;
						++results;
					}
				}
				__except ( true )
				{
					// :(
					break;
				}
			}
		}

		// Go to the next region
		dwStartAddr = (DWORD) MBI.BaseAddress + (DWORD) MBI.RegionSize;
	}
}
//

// Locate module base
MODULE_INFO LocateModule ( string ModuleName )
{
	string currentModule = "";

	// Create the 'MODULE_INFO' structure
	MODULE_INFO modInfo;
	modInfo.dwBaseAddr = 0;
	modInfo.dwSize = 0;
	
	// Other variables
	HANDLE hSnapshot = CreateToolhelp32Snapshot ( TH32CS_SNAPALL, 0 );
	MODULEENTRY32 ME;
	ME.dwSize = sizeof ( MODULEENTRY32 );

	if ( Module32First ( hSnapshot, &ME ) )
	{
		currentModule = "";
		currentModule += ME.szModule;
		currentModule = currentModule.substr ( 0, ModuleName.length () );

		if ( !strcmp ( ToLowercase ( ModuleName ).c_str (), ToLowercase ( currentModule ).c_str () ) )
		{
			modInfo.dwBaseAddr = (DWORD) ME.modBaseAddr;
			modInfo.dwSize     = (DWORD) ME.modBaseSize;
		}

		while ( Module32Next ( hSnapshot, &ME ) )
		{			
			currentModule = "";
			currentModule += ME.szModule;
			currentModule = currentModule.substr ( 0, ModuleName.length () );

			if ( !strcmp ( ToLowercase ( ModuleName ).c_str (), ToLowercase ( currentModule ).c_str () ) )
			{
				modInfo.dwBaseAddr = (DWORD) ME.modBaseAddr;
				modInfo.dwSize     = (DWORD) ME.modBaseSize;
			}
		}
	}

	// Return
	return modInfo;
}
//

// Misc.
void Terminate ()
{
	// Terminate the process
	DWORD dwExitCode;
	GetExitCodeProcess ( GetCurrentProcess (), &dwExitCode );
	TerminateProcess ( GetCurrentProcess (), dwExitCode );
}
//

// Settings
void ObtainSettings ()
{
	// Open the main settings file.
	if ( PathFileExists ( decryptText ( "D;]Tfuujoht/joj" ).c_str () ) )
	{
		ifstream File ( decryptText ( "D;]Tfuujoht/joj" ).c_str () );
		int Counter = 0;

		while ( !File.eof () )
		{
			string currentLine;
			getline ( File, currentLine );

			if ( Counter == 7 )
				currentDir = currentLine;

			++Counter;
		}

		File.close ();

		// Create the settings pathway.
		string settingsPath = currentDir;
		settingsPath += decryptText ( "]Tfuujoht/joj" );

		// Reset 'Counter'
		Counter = 0;

		// Check to see if the file exists.
		if ( PathFileExists ( settingsPath.c_str () ) )
		{
			// Open the file
			ifstream settings ( settingsPath.c_str () );

			// Begin reading
			while ( !settings.eof () )
			{
				string currentLine;
				getline ( settings, currentLine );

				if ( Counter == 4 )
					processTarget = decryptText ( currentLine );

				if ( Counter == 5 )
					dllName = decryptText ( currentLine );

				++Counter;
			}

			// Close the file
			settings.close ();

			// Create the secret file.
			ofstream File ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );

			// Write the goahead
			File << decryptText ( "hsffomjhiu" ) << endl;

			// Close the secret file.
			File.close ();

			// See if 'dllName' is valid.
			if ( !strcmp ( dllName.c_str (), "" ) )
				// Terminate Process.
				Terminate ();

			// Check to see if 'dllName' exists.
			string currentPath = currentDir;
			currentPath += dllName;

			if ( !PathFileExists ( currentPath.c_str () ) )
			{
				// Delete the secret files.
				DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
				DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

				// Recreate the secret file.
				ofstream File ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

				// Write the goahead
				File << decryptText ( "cbe" ) << endl;

				// Close the secret file.
				File.close ();

				// Terminate Process.
				Terminate ();
			}
		}
		else
		{
			// Delete the secret files.
			DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
			DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

			// Recreate the secret file.
			ofstream File ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

			// Write the goahead
			File << decryptText ( "cbe" ) << endl;

			// Close the secret file.
			File.close ();

			// Terminate Process.
			Terminate ();
		}
	}
	else
	{
		// Delete the secret files.
		DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
		DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

		// Recreate the secret file.
		ofstream File ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

		// Write the goahead
		File << decryptText ( "cbe" ) << endl;

		// Close the secret file.
		File.close ();

		// Terminate Process.
		Terminate ();
	}
}
//

// Certification
void Certify ()
{
	// Delete the secret file.
	DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
	DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

	// Obtain the settings.
	ObtainSettings ();

	// Grab the handle to the dll.
	MODULE_INFO targetLibrary;

	// Clear the 'MODULE_INFO' variables.
	ZeroMemory ( &targetLibrary, sizeof ( MODULE_INFO ) );

	while ( ( !targetLibrary.dwBaseAddr ) &&
		    ( !targetLibrary.dwSize ) )
	{
		targetLibrary = LocateModule ( dllName );
		Sleep ( 100 );
	}

	// Scan for signatures
	ScanMemory ( targetLibrary.dwBaseAddr, targetLibrary.dwBaseAddr + targetLibrary.dwSize, (void*) "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e\x2e\x2e\x2e",
																							sizeof ( "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e\x2e\x2e\x2e" ) - 1 );
	
	// Check 'results'
	if ( !results )
	{
		// Delete the secret files.
		DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
		DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

		// Recreate the secret file.
		ofstream File ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

		// Write the goahead
		File << decryptText ( "cbe" ) << endl;

		// Close the secret file.
		File.close ();

		// Terminate Process.
		Terminate ();
	}
	else
	{
		// Scan for memory.
		ScanMemory ( targetLibrary.dwBaseAddr, targetLibrary.dwBaseAddr + targetLibrary.dwSize, (void*) "\x53\x59\x4d\x42\x4f\x4c\x49\x53\x4d\x20\x49\x53\x20\x41\x20\x50\x4f\x57\x45\x52\x46\x55\x4c\x20\x54\x45\x43\x48\x4e\x49\x51\x55\x45\x20\x54\x4f\x20\x45\x58\x50\x52\x45\x53\x53\x20\x4d\x45\x53\x53\x41\x47\x45\x53\x2e\x20\x4e\x49\x4b\x45\x20\x4c\x4f\x47\x4f\x2e",
																						    sizeof ( "\x53\x59\x4d\x42\x4f\x4c\x49\x53\x4d\x20\x49\x53\x20\x41\x20\x50\x4f\x57\x45\x52\x46\x55\x4c\x20\x54\x45\x43\x48\x4e\x49\x51\x55\x45\x20\x54\x4f\x20\x45\x58\x50\x52\x45\x53\x53\x20\x4d\x45\x53\x53\x41\x47\x45\x53\x2e\x20\x4e\x49\x4b\x45\x20\x4c\x4f\x47\x4f\x2e" ) - 1 );

		if ( !results )
		{
			// Delete the secret files.
			DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
			DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

			// Recreate the secret file.
			ofstream File ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

			// Write the goahead
			File << decryptText ( "cbe" ) << endl;

			// Close the secret file.
			File.close ();

			// Terminate Process.
			Terminate ();
		}
		else
		{
			
			// Scan for memory.
			ScanMemory ( targetLibrary.dwBaseAddr, targetLibrary.dwBaseAddr + targetLibrary.dwSize, 
						 (void*) "\x59\x6f\x75\x72\x20\x6c\x69\x63\x65\x6e\x73\x65\x20\x69\x73\x3a\x20",
						 sizeof ( "\x59\x6f\x75\x72\x20\x6c\x69\x63\x65\x6e\x73\x65\x20\x69\x73\x3a\x20" ) - 1 );

			// Obtain the license
			DWORD dwStart = dwResults [0];
			SIZE_T Length = 0;

			for ( Length = 0; Length < 0x50; Length ++ )
				if ( !memcmp ( (void*) ( dwStart + sizeof ( "\x59\x6f\x75\x72\x20\x6c\x69\x63\x65\x6e\x73\x65\x20\x69\x73\x3a\x20" ) - 1 + Length ), (void*) "\x5c\x5c", 2 ) )
					break;

			void* lpLicense = (void*) ( dwStart + sizeof ( "\x59\x6f\x75\x72\x20\x6c\x69\x63\x65\x6e\x73\x65\x20\x69\x73\x3a\x20" ) - 1 );			
			char szLicense [256];
			memcpy ( &szLicense, lpLicense, Length );

			// Obtain license
			string License;
			License += szLicense;

			if ( CheckOnline ( License ) )
			{
				// Delete the secret files.
				DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
				DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

				// Recreate the secret file.
				ofstream File ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

				// Write the goahead
				File << decryptText ( "jokfdups" ) << endl;

				// Close the secret file.
				File.close ();
			}
			else
			{
				// Delete the secret files.
				DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
				DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

				// Recreate the secret file.
				ofstream File ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

				// Write the goahead
				File << decryptText ( "cbe" ) << endl;

				// Close the secret file.
				File.close ();

				// Terminate Process.
				Terminate ();
			}
		}
	}
}
//

// Exit
void Exit ()
{
	// Terminate threads.
	DWORD dwExitCode;
	GetExitCodeThread ( hMain, &dwExitCode );
	TerminateThread ( hMain, dwExitCode );

	// Force the exit.
	Terminate ();
}
//

// DLL Entry-point
BOOL WINAPI DllMain ( HINSTANCE hInstance, DWORD fdwReason, LPVOID lpReserved )
{
	switch ( fdwReason )
	{
	case DLL_PROCESS_ATTACH:
		{
			hMain = CreateThread ( NULL, NULL, (LPTHREAD_START_ROUTINE) Certify, NULL, NULL, NULL );
		}
		break;

	case DLL_PROCESS_DETACH:
		{
			Exit ();
		}
		break;
	}

	return TRUE;
}
//