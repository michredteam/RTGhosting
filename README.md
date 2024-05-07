# RTGhosting

Introduction

Several months ago, I became acquainted with a PE image manipulation technique known as  Ghosting. This method bears resemblance to Doppelgänging and Herpaderping, with the key distinction lying in the state of the PE image created. In the case of Doppelgänging, the PE image is created in a Transacted State, whereas with Process Ghosting, the PE Image enters a Delete Pending state. Consequently, this renders the file inaccessible to EDR as long as it remains on the disk.

Methodology

Understanding the code flow and methodology employed is crucial:

Begin by creating a temporary file.
Open the file using NtOpenFile, utilizing the DELETE flag for opening.
Set the file properties with NtSetInformationFile, configuring it to FileDispositionInformation. This action places the file in a delete pending state, given the initial opening with the DELETE flag.
Write the contents of the PE image into the file from which the ghost process is to be created. Ensure conversion of the binary into a byte array before writing.
Following the file write, create a section using NtCreateSection.
Upon section creation, close the file. The file will be promptly deleted from the disk upon closure, while the section created remains in memory, providing access to the section handle.
Utilizing the section handle, proceed to create a process using NtCreateProcessEx.
Calculate the entry point of the PE image and subsequently the PEB (Process Environment Block).
Proceed to write the process parameters within the created process.
Generate custom process parameters using RtlCreateProcessParametersEx.
Locate the RTL_USER_PROCESS_PARAMETERS location and from there, determine the Environment and EnvironmentSize.
Write your process parameters and environment block in the calculated location.
Finally, create a thread from the entry point of the PE image, initiating the desired process devoid of an originating binary file.

How to Use

RTGhosting.exe <path of the program to execute>

If no parameter is specified, cmd.exe will be invoked by default for practical purposes.
