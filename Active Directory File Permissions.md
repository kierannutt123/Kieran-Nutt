This project demonstrates Active Directory (AD) file and folder permissions in a small corporate environment. It simulates a realistic scenario where:
Finance Department has full access to sensitive files.
Sales Department has read-only access to shared resources.
The goal is to show proper share and NTFS permission configuration to control access based on department roles.

Both Susan in the finance department and Bob in the sales department were both able to access the shared "Finance" folder. Full permissions were given to Susan (Finance) and only read access was given to Bob (Sales)

Above are the permissions i set to the shared folder for the specific departments

As you can see from the screenshots above Susan was able to access, edit, and save a file containing sensitive financial information whereas Bob could not change the content of the file and save it back to the shared folder. 
