# OPSWAT MetaDefender Cloud API Showcase

This program was designed to display some of the functionality offered by OPSWAT's MetaDefender Cloud API's. It will allow the user to specify a file to be scanned. We will calculate the hash of this file (SHA265 | SHA1 | MD5), and perform a hash look up to see if this exact file has been previously scanned and has an existing scan report - if so, we will obtain the scan results and write out a detailed report of the findings of each individual malware engine used. Additionally, if the file is a binary file, the potential vulnerability information for this file will also be written to the detailed multiscan report. In the case that the file selected to be scanned has not been previously scanned, and does not have a pre-existing scan report, the selected file will first be scanned and uploaded via the MetaDefender Core server. Next, using the unique file data ID obtained from the file upload, the scan report is fetched from the Core server. If, based upon the scan report, the selected file is a document file, CDR will be performed on it by obtaining the raw sanitized data from the Core server, which will then be reconstructed.

### To run this program:
* Use a machine running Python 3
* It is necessary to configure Work Flow Rules based upon the type of file(s) selected to be scanned (i.e. PDF, docx, exe, etc.), since data sanitization will be performed on documents scanned for the first time.
  * To configure these settings go to the MetaDefender Core dashboard and select the file type(s) that satisfy your needs
  * This is done in Policy > Workflow rules > File process > Data Sanitization
* Ensure file selected to be scanned is in the same working directory as the source code
* In a CLI, use the command 'python main.py <file name>' to perform the logic described above on the specified file

### After running this program:
* A scan report will be generated after each file scan. Additionally, for document files being scanned and uploaded for the first time, a newly sanitized version of the original file (in binary form) will be downloaded. For PDF files, a full reconstruction of the original document will take place.


