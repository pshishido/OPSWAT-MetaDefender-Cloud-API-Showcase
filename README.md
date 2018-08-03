# OPSWAT MetaDefender Cloud API Showcase

This program was designed to display some of the functionality offered by OPSWAT's MetaDefender Cloud API's. It will allow the user to specify a file to be scanned. We will calculate the hash of this file (SHA265 | SHA1 | MD5), and perform a hash look up to see if this exact file has been previously scanned and has an existing scan report - if so, we will obtain the scan results and write out a detailed report of the findings of each individual malware engine used. In the case that the file selected to be scanned has not been previously scanned, and does not have a pre-existing scan report, the selected file will first be scanned and uploaded via MetaDefender Cloud. Next, using the unique file data ID obtained from the file upload, the scan report is fetched from the Cloud server. If, based upon the scan report, the selected file is a document file (pdf,doc, etc.), CDR will be performed on it by first performing data sanitization, and subsequently obtaining a download link to the sanitized binary data from the Cloud server.

### To run this program:
* Use a machine running Python 3
* Ensure file selected to be scanned is in the same working directory as the source code
* In a CLI, use the command 'python main.py <file name>' to perform the logic described above on the specified file

### After running this program:
* A scan report will be generated after each file scan. 
* Additionally, for document files being scanned and uploaded for the first time, a download link to the sanitized binary data will be logged to the console.


