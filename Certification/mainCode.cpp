#include "Certification.h"

// Global Variables
HWND hWnd = NULL;

// Main Callbacks
INT_PTR CALLBACK MainProc ( HWND hWndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam )
{
	hWnd = hWndDlg;

	switch ( uMsg )
	{
		case WM_COMMAND:
		{
			switch ( wParam )
			{
			// Browse.
			case IDC_BUTTON1:
				{
					// Create variables
					OPENFILENAME ofn;
					char szBuffer [260];

					// Initialize OPENFILENAME
					ZeroMemory ( &ofn, sizeof(ofn) );

					ofn.lStructSize = sizeof ( ofn );
					ofn.hwndOwner = hWnd;
					ofn.lpstrFile = szBuffer;
					ofn.lpstrFile[0] = '\0';
					ofn.nMaxFile = sizeof ( szBuffer );
					ofn.lpstrFilter = ".DLL File\0*.dll*\0\0";
					ofn.nFilterIndex = 1;
					ofn.lpstrFileTitle = "Select your .DLL File";
					ofn.nMaxFileTitle = 0;
					ofn.lpstrInitialDir = "C:\\";
					ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

					// Open the dialog
					if ( GetOpenFileName (&ofn) == TRUE )
					{
						if ( strcmp ( szBuffer, "" ) != 0 )
						{
							SetWindowText ( GetDlgItem ( hWnd, IDC_EDIT1 ), szBuffer );

							// Obtain the dll name
							string dllName;
							dllName += (LPSTR) szBuffer;
							dllName = dllName.substr ( dllName.find_last_of ( "\\" ) + 1, dllName.length () );

							// Set the new window title
							SetWindowText ( GetDlgItem ( hWndDlg, IDC_EDIT2 ), dllName.c_str () );
						}
					}
				}
				break;

			// Certify.
			case IDC_BUTTON2:
				{
					// Obtain the dll path
					char szBuffer [256];
					GetWindowText ( GetDlgItem ( hWndDlg, IDC_EDIT1 ), szBuffer, 256 );

					if ( strcmp ( szBuffer, "" ) != 0 )
					{
						// Convert into string.
						string dllPathway;
						dllPathway += szBuffer;

						// Certify.
						int certifyLib = Certify ( dllPathway );

						// Check results.
						if ( certifyLib == 0 )
							MessageBoxA ( hWndDlg, "Something went wrong!", "Error 0x001", MB_ICONERROR );
						else if ( certifyLib == 1 )
							MessageBoxA ( hWndDlg, "Something went wrong!", "Error 0x002", MB_ICONERROR );
						else if ( certifyLib == 2 )
							MessageBoxA ( hWndDlg, "The module is already certified!", "Error 0x002", MB_ICONERROR );
						else if ( certifyLib == 3 )
							MessageBoxA ( hWndDlg, "The signatures can't be found!", "Error 0x003", MB_ICONERROR ); 
						else if ( certifyLib == 4 )
							MessageBoxA ( hWndDlg, "The signatures can't be found!", "Error 0x004", MB_ICONERROR );
						else if ( certifyLib == 5 )
							MessageBoxA ( hWndDlg, "The module was certified!", "Success", MB_ICONINFORMATION );
						else if ( certifyLib == 6 )
							MessageBoxA ( hWndDlg, "The DLL path is not valid.", "Error", MB_ICONERROR );
					}
				}
				break;

			// Generate a settings file.
			case IDC_BUTTON3:
				{
					// Obtain the dll path.
					char szBuffer [256];
					GetWindowText ( GetDlgItem ( hWndDlg, IDC_EDIT1 ), szBuffer, 256 );
		
					if ( strcmp ( szBuffer, "" ) != 0 )
					{
						// Obtain the library name.
						char szLibrary [256];
						GetWindowText ( GetDlgItem ( hWndDlg, IDC_EDIT2 ), szLibrary, 256 );

						if ( strcmp ( szLibrary, "" ) != 0 )
						{
							// Obtain the process name.
							char szProcess [256];
							GetWindowText ( GetDlgItem ( hWndDlg, IDC_EDIT3 ), szProcess, 256 );

							if ( strcmp ( szProcess, "" ) != 0 )
							{
								// Convert to string
								string pathway;
								pathway += (LPSTR) szBuffer;
								pathway = pathway.substr ( 0, pathway.find_last_of ( "\\" ) );

								string library;
								library += (LPSTR) szLibrary;

								string process;
								process += (LPSTR) szProcess;

								// Generate a settings file
								GenerateSettings ( pathway, process, library );

								// Message
								MessageBoxA ( hWndDlg, "The settings file has been generated!", "Success!", MB_ICONINFORMATION );
							}
						}						
					}
				}
				break;
			}

			return TRUE;
		}

	case WM_INITDIALOG:
		{
			// Setup window text
			SetWindowText ( GetDlgItem ( hWndDlg, IDC_EDIT1 ), "C:\\mydll.dll" );
			SetWindowText ( GetDlgItem ( hWndDlg, IDC_EDIT2 ), "mydll.dll" );
			SetWindowText ( GetDlgItem ( hWndDlg, IDC_EDIT3 ), "WolfTeam.bin" );

			return TRUE;
		}

	case WM_CLOSE:
		{
			EndDialog ( hWndDlg, 0 );
			return TRUE;
		}

	default:
		return FALSE;
	}
}
INT_PTR CALLBACK LicenseProc ( HWND hWndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam )
{
	switch ( uMsg )
	{
	case WM_INITDIALOG:
		{
			SetWindowText ( GetDlgItem ( hWndDlg, IDC_EDIT1 ), GetLicense ().c_str () );

			return TRUE;
		}

	case WM_CLOSE:
		{
			EndDialog ( hWndDlg, 0 );
			return TRUE;
		}

	default:
		return FALSE;
	}
}
//

// Main Entry-point
int CALLBACK WinMain ( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
{
	// Vertify license.
	//if ( true )//CheckOnline ( GetLicense () ) )
		DialogBoxA ( hInstance, MAKEINTRESOURCE ( IDD_DIALOG1 ), NULL, MainProc );
	//else
	//	DialogBoxA ( hInstance, MAKEINTRESOURCE ( IDD_DIALOG2 ), NULL, LicenseProc );

	// Close the application
	DWORD dwExitCode;
	GetExitCodeProcess ( GetCurrentProcess (), &dwExitCode );
	TerminateProcess ( GetCurrentProcess (), dwExitCode );

	return 0;
}
//