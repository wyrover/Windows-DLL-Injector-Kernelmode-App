#include "Authorization.h"

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

// Certify a non-certified library.
int Certify ( string dllPathway )
{
	if ( !PathFileExists ( dllPathway.c_str () ) )
		return 6;
	else
	{
		SIZE_T dllSize;
		struct stat st;
		
		// Obtain the size of the DLL.
		if ( stat ( dllPathway.c_str (), &st ) == 0)
			dllSize = st.st_size;

		// Check the size of the DLL.
		if ( dllSize != 0 )
		{
			// Open the file.
			HANDLE hFile = CreateFile ( dllPathway.c_str (), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

			// Check the file
			if ( hFile != 0 )
			{
				// Read the file
				void* allocatedMem = VirtualAlloc ( 0, dllSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

				DWORD bytesRead;			
				ReadFile ( hFile, allocatedMem, dllSize, &bytesRead, NULL );

				// Close the file
				CloseHandle ( hFile );

				// Check to see if the file is already certified
				for ( SIZE_T addr = 0; addr < dllSize - sizeof ( "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e\x2e\x2e\x2e" ) - 1; addr ++ )
					if ( !memcmp ( (void*) ( (DWORD) allocatedMem + (DWORD) addr ), (void*) "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e\x2e\x2e\x2e",
																					  sizeof ( "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e\x2e\x2e\x2e" ) - 1 ) )
						return 2;

				SIZE_T addr;

				// Look for the non-certified signature
				for ( addr = 0; addr < dllSize - sizeof ( "\x4e\x4f\x20\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e" ) - 1; addr ++ )
					if ( !memcmp ( (void*) ( (DWORD) allocatedMem + (DWORD) addr ), (void*) "\x4e\x4f\x20\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e",
																					  sizeof ( "\x4e\x4f\x20\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e" ) - 1 ) )
						break;

				if ( ( addr == 0 ) ||
					 ( addr == dllSize ) )
					return 4;
				else
				{
					// Change the signature
					memcpy ( (void*) ( (DWORD) allocatedMem + (DWORD) addr ), (void*) "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e\x2e\x2e\x2e", 
																			   sizeof ( "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x49\x4f\x4e\x20\x4b\x45\x59\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45\x2e\x2e\x2e\x2e" ) - 1 );

					// Look for the license key
					for ( addr = 0; addr < dllSize - sizeof ( "\x59\x6f\x75\x72\x20\x6c\x69\x63\x65\x6e\x73\x65\x20\x69\x73\x3a\x20" ) - 1; addr ++ )
						if ( !memcmp ( (void*) ( (DWORD) allocatedMem + (DWORD) addr ), (void*) "\x59\x6f\x75\x72\x20\x6c\x69\x63\x65\x6e\x73\x65\x20\x69\x73\x3a\x20",
																						sizeof ( "\x59\x6f\x75\x72\x20\x6c\x69\x63\x65\x6e\x73\x65\x20\x69\x73\x3a\x20" ) - 1 ) )
																						break;

					if ( ( addr == 0 ) ||
						 ( addr == dllSize ) )
						 return 3;
					else
					{
						string License = GetLicense ();

						// Create the license key
						LPVOID licenseKey = VirtualAlloc ( 0, License.length () + 0x02, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

						// Setup the license key
						LPCSTR LicenseStr;
						LicenseStr = License.c_str ();

						memcpy ( licenseKey, (void*) LicenseStr, strlen ( LicenseStr ) );
						memcpy ( (void*) ( (DWORD) licenseKey + GetLicense ().length () ), (void*) "\x5c\x5c", 2 );

						// Set the license key
						memcpy ( (void*) ( (DWORD) allocatedMem + (DWORD) addr + sizeof ( "\x59\x6f\x75\x72\x20\x6c\x69\x63\x65\x6e\x73\x65\x20\x69\x73\x3a\x20" ) - 1 ), licenseKey, License.length () + 2 );

						// Obtain the new pathway
						string fileName;
						fileName = dllPathway.substr ( dllPathway.find_last_of ( "\\" ) + 1, dllPathway.length () );

						string newPath;
						newPath = dllPathway.substr ( 0, dllPathway.find_last_of ( "\\" ) );

						// The new file name.
						string newFile;
						newFile += newPath;
						newFile += "\\";
						newFile += fileName;
						newFile += ".tmp";

						// The replacement name.
						string newName;
						newName += newPath;
						newName += "\\";
						newName += fileName;

						// Delete the old file
						DeleteFile ( newFile.c_str () );

						// Create the new file
						hFile = CreateFile ( newFile.c_str (), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );

						// Write the new file
						WriteFile ( hFile, allocatedMem, dllSize, &bytesRead, NULL );

						// Close the file
						CloseHandle ( hFile );

						// Delete the main file
						DeleteFile ( dllPathway.c_str () );

						// Rename the other file
						MoveFileA ( newFile.c_str (), newName.c_str () );

						// Get rid of the allocation
						VirtualFree ( allocatedMem, dllSize, MEM_RELEASE );

						// Finish
						return 5;
					}
				}
			}
			else
				return 1;
		}
		else
			return 0;
	}
}
//

// Generate random variables.
int    GenerateRandomInt ()
{
	return rand () % 10 + 8;
}
string GenerateRandomStr ( int length )
{
	string randStr = "";
	int randNum    = 0;

	for ( int i = 0; i < length; i ++ )
	{
		randNum = rand () % 25 + 0;
		randStr += (char) ( 'a' + randNum );
	}

	return randStr;
}
//

// Generate an encrypted settings file.
void GenerateSettings ( string pathway, string process, string name )
{
	// Generate the string.
	string filePath;
	filePath += pathway;
	filePath += "\\Settings.ini";

	// Delete the current settings file.
	DeleteFile ( filePath.c_str () );

	// Create the new settings file.
	ofstream File ( filePath.c_str () );

	srand ( (unsigned int) time ( NULL ) );

	// Write the information
	for ( int i = 0; i < 4; i ++ )
		File << GenerateRandomStr ( GenerateRandomInt () ) << endl;

	File << encryptText ( process ) << endl;
	File << encryptText ( name ) << endl;

	for ( int i = 0; i < 2; i ++ )
		File << GenerateRandomStr ( GenerateRandomInt () ) << endl;

	// Close the file
	File.close ();
}
//