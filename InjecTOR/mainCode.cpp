#include "Authorization.h"

/*
	# This is the loading component.
	# There are two versions:
		1. Developper Version (Ability to launch InjecTOR.exe w/o protection checks for their users)
		2. Public Version (Protection checks for everybody)
	# Brainstorm 

	1. Determine processor type
	2. Determine the function to find (pathway to find ZwProtectVirtualMemory)
		# 32 Bit - ZwPulseEvent
		# 64 Bit - ZwQuerySection
	3. Write down information (Process ID of target, processor type, functions needed, target function)
	4. Launch the driver
*/

HINSTANCE hInst = NULL;

// Global Variables
SC_HANDLE driverHandle = NULL;
HANDLE    hInitWind;
HWND      hWndDlg;

// Injection Success
BOOL Injected = FALSE;

// Target Variable
string processTarget; // Not case-sensitive
string DllName;       // Case-sensitive

// Platform Variable
BOOL environmentType;

// Close the application
BOOL CloseApp = FALSE;

// Window Procedures.
INT_PTR CALLBACK MainDlg ( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam );
INT_PTR CALLBACK TargetApp ( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam );
INT_PTR CALLBACK LicenseDlg ( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam );

// Debugging Function.
template <class T> void la ( T Value )
{
	stringstream ss;
	ss << Value;
	string str;
	str += ss.str ();
	MessageBox ( 0, str.c_str (), 0, 0 );
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

// Scan.
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
DWORD Scan ( string processName )
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot ( TH32CS_SNAPALL, 0 );
	PROCESSENTRY32 PE;
	PE.dwSize = sizeof ( PROCESSENTRY32 );

	if ( Process32First ( hSnapshot, &PE ) )
		while ( Process32Next ( hSnapshot, &PE ) )
			if ( !strcmp ( ToLowercase ( PE.szExeFile ).c_str (), processName.c_str () ) )
				return PE.th32ProcessID;

	return -1;
}
//

// Load Driver.
SC_HANDLE LoadDriver ()
{
	string pathway;
	char szDirectory [256];
	GetCurrentDirectory ( 256, szDirectory );
	pathway += szDirectory;
	pathway += "\\InjecTOR.sys";

	// Check if InjecTOR.dll exists.
	string injecTORPath;
	injecTORPath += szDirectory;
	injecTORPath += "\\InjecTOR.dll";

	if ( PathFileExists ( injecTORPath.c_str () ) )
	{
		if ( PathFileExists ( pathway.c_str () ) )
		{
			SC_HANDLE manager = OpenSCManager ( 0, 0, SC_MANAGER_ALL_ACCESS ); 

			// Create/Open the driver
			SC_HANDLE driver = OpenService ( manager, "InjecTOR", SC_MANAGER_ALL_ACCESS );

			if ( !driver )
				driver = CreateService ( manager, "InjecTOR", "InjecTOR", SC_MANAGER_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
										 SERVICE_ERROR_NORMAL, pathway.c_str (), NULL, NULL, NULL, NULL, NULL );

			if ( !driver )
				return 0;

			// Start the driver
			if ( StartService ( driver, NULL, NULL ) )
			{
				SetWindowText ( GetDlgItem ( hWndDlg, IDC_STATUS ), "Driver has loaded." );

				// Close and delete the driver
				SERVICE_STATUS ss;
				ControlService ( driver, SERVICE_CONTROL_STOP, &ss );
				DeleteService ( driver);
				CloseServiceHandle ( driver );
			}
			else
			{
				MessageBoxA ( hWndDlg, "The driver has failed to load.", "Error: 0x002", MB_ICONERROR );
				
				// Delete existing files.
				DeleteFile ( decryptText ( "D;]Tfuujoht/joj" ).c_str () );
				DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );

				// Terminate process.
				DWORD dwExitCode;
				GetExitCodeProcess ( GetCurrentProcess (), &dwExitCode );
				TerminateProcess ( GetCurrentProcess (), dwExitCode );

				return 0;
			}

			CloseServiceHandle ( manager );

			CloseApp = TRUE;
			return driver;
		}
		else
		{
			MessageBoxA ( hWndDlg, "Your missing the driver (.sys)!", "Error 0x006", MB_ICONINFORMATION );

			// Delete existing files.
			DeleteFile ( decryptText ( "D;]Tfuujoht/joj" ).c_str () );
			DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );

			// Terminate process.
			DWORD dwExitCode;
			GetExitCodeProcess ( GetCurrentProcess (), &dwExitCode );
			TerminateProcess ( GetCurrentProcess (), dwExitCode );

			return 0;
		}
	}
	else
	{
		MessageBoxA ( hWndDlg, "Your missing the dll (.dll)!", "Error 0x007", MB_ICONINFORMATION );

		// Delete existing files.
		DeleteFile ( decryptText ( "D;]Tfuujoht/joj" ).c_str () );
		DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );

		// Terminate process.
		DWORD dwExitCode;
		GetExitCodeProcess ( GetCurrentProcess (), &dwExitCode );
		TerminateProcess ( GetCurrentProcess (), dwExitCode );

		return 0;
	}
}
//

// Main Functions.
void initSettings ()
{
	int counter = 0;

	// Get the current directory
	char szCurrentDir [256];
	GetCurrentDirectoryA ( 256, (LPSTR) szCurrentDir );

	// Create the settings pathway
	string settingsPath;
	settingsPath += (LPSTR) szCurrentDir;
	settingsPath += "\\Settings.ini";

	if ( PathFileExists ( settingsPath.c_str () ) )
	{
		// Open the file
		ifstream settings ( settingsPath.c_str () );

		// Begin reading
		while ( !settings.eof () )
		{
			string currentLine;
			getline ( settings, currentLine );

			if ( counter == 4 )
				processTarget = decryptText ( currentLine );

			if ( counter == 5 )
				DllName = decryptText ( currentLine );

			++counter;
		}

		// Close the file
		settings.close ();

		// Obtain the user target.
		DialogBoxA ( hInst, MAKEINTRESOURCE ( IDD_DIALOG3 ), NULL, TargetApp );

		// Check to see if 'dllName' exists.
		string currentPath;
		currentPath += (LPSTR) szCurrentDir;
		currentPath += "\\";
		currentPath += DllName;

		if ( !PathFileExists ( currentPath.c_str () ) )
		{
			string msg = "Your library ";
			msg += DllName;
			msg += " is missing.";

			// Send a message
			MessageBoxA ( hWndDlg, msg.c_str (), "Error", MB_ICONERROR );

			// Terminate Process.
			Terminate ();
		}
		else
		{
			// Create the secret file.
			ofstream File ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );

			// Write the goahead
			File << decryptText ( "hsffomjhiu" ) << endl;

			// Close the secret file.
			File.close ();
		}
	}
	else
	{
		MessageBoxA ( hWndDlg, "Your missing a settings file!", "Error 0x004", MB_ICONINFORMATION );
		
		// Delete existing files.
		DeleteFile ( decryptText ( "D;]Tfuujoht/joj" ).c_str () );
		DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );

		// Terminate process.
		DWORD dwExitCode;
		GetExitCodeProcess ( GetCurrentProcess (), &dwExitCode );
		TerminateProcess ( GetCurrentProcess (), dwExitCode );
	}
}
void initInjecTOR ()
{
	// Update Status
	SetWindowText ( GetDlgItem ( hWndDlg, IDC_STATUS ), "Collecting data." );
	Sleep ( 1000 );

	// Collect information
	DWORD dwTargetId = Scan ( ToLowercase ( processTarget.c_str () ) );

	if ( dwTargetId == -1 )
	{
		CloseApp = TRUE;
		MessageBoxA ( hWndDlg, "Please open the target application.", "Error 0x001", MB_ICONERROR );
		
		// Delete existing files.
		DeleteFile ( decryptText ( "D;]Tfuujoht/joj" ).c_str () );
		DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );

		// Terminate process.
		DWORD dwExitCode;
		GetExitCodeProcess ( GetCurrentProcess (), &dwExitCode );
		TerminateProcess ( GetCurrentProcess (), dwExitCode );
	}
	else
	{
		// Obtain current directory
		char szBuffer [256];
		GetCurrentDirectory ( 256, (LPSTR) szBuffer );
		string curDir;
		curDir += (LPSTR) szBuffer;

		if ( curDir.at ( curDir.length () - 1 ) != '\\' )
			curDir += "\\";

		// Setup 'DllPath'
		string DllPath;
		DllPath += curDir;
		DllPath += DllName;
		SIZE_T dllSize = 0;

		// Obtain the size of the DLL
		struct stat st;

		if ( stat ( DllPath.c_str (), &st ) == 0)
			dllSize = st.st_size;

		if ( dllSize != 0 )
		{
			// Determine processor type
			IsWow64Process ( GetCurrentProcess (), &environmentType );

			// Check for a Windows 8.
			OSVERSIONINFOEX osVersion;
			osVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
			GetVersionEx ( (OSVERSIONINFOA*) &osVersion );

			// Determine if its 32 Bit.
			bool Windows8 = ( ( osVersion.dwMajorVersion == 6 ) && ( osVersion.dwMinorVersion == 2 ) ) ? true : false;

			// Create settings file
			SECURITY_ATTRIBUTES secAttrib;
			secAttrib.nLength = sizeof ( SECURITY_ATTRIBUTES );
			secAttrib.lpSecurityDescriptor = NULL;
			secAttrib.bInheritHandle = FALSE;
			ofstream settings ( decryptText ( "D;]Tfuujoht/joj" ).c_str () );

			// Write the settings 
			settings << environmentType << endl;
			settings << Windows8 << endl;
			settings << (void*) dwTargetId << endl;
			settings << (void*) CreateThread << endl;
			settings << (void*) LoadLibraryA << endl;
			settings << (void*) Sleep << endl;
			settings << (void*) VirtualProtect << endl;
			settings << curDir.c_str () << endl;
			settings << DllName.c_str () << endl;
			settings << (void*) dllSize << endl;
			settings << "end" << endl;

			// Close the file
			settings.close ();

			// Update Status
			SetWindowText ( GetDlgItem ( hWndDlg, IDC_STATUS ), "Starting the driver." );
			Sleep ( 1000 );

			// Start the driver
			driverHandle = LoadDriver ();

			// Set 'CloseApp'
			CloseApp = TRUE;

			// Sleep
			Sleep ( 2000 );

			// Set 'Injected'
			Injected = TRUE;

			// Close the dialog
			EndDialog ( hWndDlg, 0 );
		}
		else
		{
			CloseApp = TRUE;
			MessageBoxA ( 0, "Dll Error!", "Error 0x003", MB_ICONERROR );

			// Delete existing files.
			DeleteFile ( decryptText ( "D;]Tfuujoht/joj" ).c_str () );
			DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );

			// Terminate process.
			DWORD dwExitCode;
			GetExitCodeProcess ( GetCurrentProcess (), &dwExitCode );
			TerminateProcess ( GetCurrentProcess (), dwExitCode );
		}
	}
}
//

// Callbacks.
INT_PTR CALLBACK MainDlg ( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam )
{
	hWndDlg = hWnd;

	switch ( uMsg )
	{
	case WM_INITDIALOG:
		{
			// Set the person's name.
			SetWindowText ( GetDlgItem ( hWnd, IDC_NAME ), Name.c_str () );

			// Obtain the settings
			initSettings ();

			if ( strcmp ( processTarget.c_str (), "" ) != 0 )
			{
				if ( strcmp ( DllName.c_str (), "" ) != 0 )
					hInitWind = CreateThread ( NULL, NULL, (LPTHREAD_START_ROUTINE) initInjecTOR, NULL, NULL, NULL );
			}
			else
			{
				MessageBoxA ( hWnd, "Your settings file is corrupt!", "Error 0x005", MB_ICONINFORMATION );
				Terminate ();
			}

			return TRUE;
		}

	case WM_CLOSE:
		{
			// Close the Window
			if ( CloseApp )
				EndDialog ( hWndDlg, 0 );

			// Stop the driver
			if ( driverHandle != NULL )
			{
				SERVICE_STATUS ss;
				ControlService ( driverHandle, SERVICE_CONTROL_STOP, &ss );
				DeleteService ( driverHandle );
				CloseServiceHandle ( driverHandle );
			}

			return TRUE;
		}

	default:
		return FALSE;
	}
}
INT_PTR CALLBACK TargetApp ( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam )
{
	switch ( uMsg )
	{
	case WM_COMMAND:
		{
			switch ( wParam )
			{
			case IDC_BUTTON1:
				{
					char szBuffer [256];
					GetWindowText ( GetDlgItem ( hWnd, IDC_EDIT1 ), szBuffer, 256 );
					processTarget = "";
					processTarget += szBuffer;
					EndDialog ( hWnd, 0 );
				}
				break;
			}

			return TRUE;
		}

	case WM_INITDIALOG:
		{
			SetWindowText ( GetDlgItem ( hWnd, IDC_EDIT1 ), "WolfTeam.bin" );

			return TRUE;
		}

	case WM_CLOSE:
		{
			EndDialog ( hWnd, 0 );
			return TRUE;
		}

	default:
		return FALSE;
	}
}
INT_PTR CALLBACK LicenseDlg ( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam )
{
	switch ( uMsg )
	{
	case WM_INITDIALOG:
		{
			SetWindowText ( GetDlgItem ( hWnd, IDC_STATUS ), GetLicense ().c_str () );

			return TRUE;
		}

	case WM_CLOSE:
		{
			EndDialog ( hWnd, 0 );
			return TRUE;
		}
		
	default:
		return FALSE;
	}
}
//

// Main Entry-point.
int CALLBACK WinMain ( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
{
	hInst = hInstance;

	// Delete existing files.
	DeleteFile ( decryptText ( "D;]Tfuujoht/joj" ).c_str () );
	DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
	DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

	if ( !IsDebuggerPresent () )
	{
		//if ( CheckOnline ( GetLicense () ) )
		//{
			// Run the Main Dialog
			DialogBoxA ( hInstance, MAKEINTRESOURCE ( IDD_DIALOG1 ), NULL, MainDlg );

			// Stop the driver
			if ( driverHandle != NULL )
			{
				SERVICE_STATUS ss;
				ControlService ( driverHandle, SERVICE_CONTROL_STOP, &ss );
				DeleteService ( driverHandle );
				CloseServiceHandle ( driverHandle );
			}

			// Close the thread
			DWORD dwExitCode;
			GetExitCodeThread ( hInitWind, &dwExitCode );
			TerminateThread ( hInitWind, dwExitCode );

			// If everything worked.
			if ( Injected )
			{
				// Wait for the process to unload.
				DWORD dwProcessID = 0;

				while ( dwProcessID != -1 )
				{
					// Scan for the process
					dwProcessID = Scan ( ToLowercase ( processTarget ) );

					// Rest
					Sleep ( 500 );
				}
			}
		//}
		//else
			// Run the License Dialog
		//	DialogBoxA ( hInstance, MAKEINTRESOURCE ( IDD_DIALOG2 ), NULL, LicenseDlg );
	}

	// Delete existing files.
	DeleteFile ( decryptText ( "D;]Xjoepxt]hsffomjhiu/uyu" ).c_str () );
	DeleteFile ( decryptText ( "D;]jokfdups/uyu" ).c_str () );

	return 0;
}
//