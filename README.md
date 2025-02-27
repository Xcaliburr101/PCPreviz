## LaptopPreviz

### Description

This PowerShell script is designed to gather and display comprehensive information about a Windows system. It retrieves details about hardware components, system configuration, connected devices, and potential system issues. This tool is useful for system diagnostics, inventory management, or simply understanding your computer's specifications.

## Features

*   **System Information:**
    *   System Model
    *   Serial Number
    *   Secure Boot Status (Enabled/Disabled)
    *   TPM (Trusted Platform Module) Status

*   **Hardware Information:**
    *   Processor Name and Speed
    *   Total RAM
    *   Screen Size (in inches)
    *   Network Link Speed (for active WiFi and Ethernet connections)

*   **Audio Devices:**
    *   Detected Speakers
    *   Microphone Detection Status and Name

*   **Storage Devices:**
    *   Detailed information for each fixed disk drive:
        *   Device Name
        *   Model
        *   Drive Type (HDD, SSD, NVMe)
        *   Size
        *   Interface Type

*   **Webcam Check:**
    *   Detected Webcam Device Name

*   **Problem Detection:**
    *   Identifies and lists devices with driver issues (excluding disabled devices), providing:
        *   Device Name
        *   Error Code
        *   Error Description

*   **Research & Utilities:**
    *   Prompts to search for hard drive models on SmartHDD.com via Google.
    *   Opens the "Printers & scanners" settings page.
    *   Attempts to open Device Manager .

*   **BIOS Reboot (Conditional):**
    *   If Secure Boot is disabled and the script is run with Administrator rights, it offers to reboot directly into the BIOS/UEFI settings.



### Prerequisites

*   **Operating System:** Windows (This script is designed for Windows and utilizes Windows-specific tools and APIs).
*   **PowerShell:** Ensure you have PowerShell installed. It is typically pre-installed on modern Windows systems.
*   **Administrator Rights (Optional but Recommended):**  While the script will run without administrator privileges, some features (like Secure Boot and TPM status, Device Manager access, and BIOS reboot) require administrator rights to function correctly. Running the script as an administrator will provide the most complete information.

1.  **Run the Script:**
    *   In an *elevated* terminal(ctrl+shift click), type the following command and press Enter:
        ```powershell
        powershell.exe -ExecutionPolicy Bypass -File "D:\Tools\1CheckLaptop.ps1"
        ```
*	Or use / modify the shortcut in the repo
---


## Troubleshooting and Notes

*   **Administrator Rights:** Some features, particularly those related to system security settings (Secure Boot, TPM), require administrator rights. Run PowerShell as Administrator to access all features.

*   **PowerShell Execution Policy:** If you encounter errors related to script execution, ensure that your PowerShell execution policy allows running local scripts. While the script attempts to bypass the policy for the current process, you may need to adjust it more broadly if you face issues. You can check your current execution policy with `Get-ExecutionPolicy -List`.

*   **External Websites & BIOS Reboot:** The script interacts with external websites (Google Search for SmartHDD) and offers to reboot your system into BIOS. Exercise caution and review these actions before proceeding, especially when prompted to reboot into BIOS as it will restart your computer.

*   **Output Colors:** The script uses color formatting in PowerShell for better readability. These colors might not be visible in all terminal environments or if PowerShell is configured to not display colors.

*   **Error Handling:** The script includes `try-catch` blocks to handle potential errors gracefully and provide informative messages. If you encounter errors, review the error messages in the PowerShell console for clues.

*   **Internet Connection (Optional):** An internet connection is only required if you choose to perform the SmartHDD.com Google searches. The core system information gathering functions do not require internet access.

---
