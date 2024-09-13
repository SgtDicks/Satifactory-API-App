**Version:** 0.0.1  
**Release Date:** September 14, 2024

---

### **Overview**
Please note this was all written by Chatgpt, I am just to lazy to write it all out
I am looking to do a standalone app soon that will store server details and the API key for the servers, but working on the code, ill update this soon


The **Dedicated Server API Client GUI** is a powerful and user-friendly tool designed to facilitate seamless interaction with your Satisfactory dedicated server's API. Whether you're managing server settings, executing commands, or handling game sessions, this GUI provides an intuitive interface to streamline your workflow.

---

### **New Features**

1. **Comprehensive API Functionality**
   - **Wide Range of API Functions:** Access and execute various server-side functions such as `HealthCheck`, `VerifyAuthenticationToken`, `PasswordLogin`, `QueryServerState`, `CreateNewGame`, `SaveGame`, and more.
   - **Dynamic Parameter Management:** Automatically generates input fields based on the selected API function, supporting multiple data types including strings, passwords, enums, booleans, dictionaries, and integers.

2. **Multiple Authentication Methods**
   - **Bearer Token Authentication:** Securely authenticate using a bearer token.
   - **Passwordless Login:** Authenticate without a password by specifying a minimum privilege level.
   - **Password Login:** Authenticate using a password along with a specified privilege level.
   - **Dynamic Authentication Fields:** The GUI dynamically adjusts input fields based on the selected authentication method.

3. **File Handling Capabilities**
   - **Upload and Download Files:** Easily upload save game files or download them directly through the interface.
   - **File Selection Dialogs:** Intuitive file selection dialogs for choosing files to upload or specifying save locations for downloads.

4. **User-Friendly Interface**
   - **Tkinter-Based GUI:** Clean and responsive design built with Tkinter, ensuring compatibility across various operating systems.
   - **Scrolled Response Display:** View API responses in a dedicated scrolled text area for easy reading and troubleshooting.
   - **Informative Messages:** Receive real-time feedback through message boxes for successful operations, errors, and other notifications.

5. **Robust Logging**
   - **Detailed Logs:** All actions, requests, and responses are logged to `api_client_gui.log` for auditing and debugging purposes.
   - **Error Tracking:** Capture and log detailed error messages to assist in quick issue resolution.


---

### **Bearer Token Authentication Instructions**

To authenticate using a Bearer Token, follow these steps:

1. **Access Server Console:**
   - Connect to your Satisfactory Dedicated Server's console via SSH, RCON, or another remote management tool.

2. **Run the GenerateAPIToken Command:**
Run the following command from the Satisfactory server manager in game in the console field
   ```
   server.GenerateAPIToken
   ```
   - The server will respond with a new Application Token.
   - it should looks a little like this 
   - 
![image](https://github.com/user-attachments/assets/ba57e95b-e091-4f49-b8d9-32b6754ec0a1)


4. **Use the Application Token in GUI:**
   - Launch the GUI.
   - In the "Authentication" section, select "Bearer Token" from the dropdown.
   - Enter the newly generated Application Token in the "Bearer Token" field.
   - Click "Authenticate" to set the token for subsequent requests.
![image](https://github.com/user-attachments/assets/74e3e01a-219c-4390-b4a6-6096d50810f3)
![image](https://github.com/user-attachments/assets/87cf8d84-5856-4fd7-a5a5-ca005910e200)


5. **Confirm Authentication:**
   - Upon successful authentication, a confirmation message like "Bearer Token authentication successful" should appear.
   - The `AuthenticationToken` is now stored within the GUI for subsequent API requests.

---

### **Enhancements**

- **Parameter Validation:** Enhanced input validation to ensure all required fields are correctly filled before sending requests.
- **Authentication Token Management:** Automatically updates and manages authentication tokens upon successful login operations.
- **Improved Error Handling:** More descriptive error messages and logging to aid in diagnosing issues quickly.

---

### **Bug Fixes**

- **InsecureRequestWarning Suppression:** Specifically disables only the `InsecureRequestWarning` from `urllib3` to avoid unnecessary warnings without compromising other security alerts.
- **File Resource Management:** Ensures that file resources are properly closed after upload operations to prevent resource leaks.

---

### **Known Issues**

- **SSL Verification Disabled by Default:** For environments requiring secure SSL communication, users must manually enable SSL verification in the `APIClient` class.
- **Limited API Function Coverage:** Currently supports a specific set of API functions. Additional functions may require further development and integration.

---

### **Installation**

1. **Prerequisites:**
   - **Python 3.6 or higher** installed on your system.
   - **pip** package manager.

2. **Install Required Dependencies:**
   ```bash
   pip install requests
   ```

3. **Download the GUI:**
   - Save the provided Python script to your local machine, e.g., `api_client_gui.py`.

4. **Run the Application:**
   ```bash
   python api_client_gui.py
   ```

---

### **Usage Instructions**

1. **Launch the GUI:**
   - Run the script to open the Satisfactory Dedicated Server API Client interface.

2. **Configure Server Connection:**
   - **Host:** Enter the server hostname or IP address (default is `localhost`).
   - **Port:** Enter the server port number (default is `7777`).

3. **Authenticate:**
   - **Select Authentication Method:** Choose between `Bearer Token`, `Passwordless Login`, or `Password Login`.
   - **Provide Credentials:** Depending on the selected method, enter the required token or password information.
   - **Click "Authenticate":** Establish a session with the server.

4. **Select API Function:**
   - **Choose Function:** From the dropdown menu, select the desired API function to execute.
   - **Enter Parameters:** Fill in the dynamically generated input fields based on the selected function's requirements.

6. **Handle Files (If Applicable):**
   - **Upload/Download:** Use the "Select File" button to choose files for upload or specify save locations for downloads.

7. **Send Request:**
   - **Click "Send Request":** Execute the API function with the provided parameters.
   - **View Response:** The server's response will be displayed in the response section for review.
![image](https://github.com/user-attachments/assets/6c6e80f9-74f2-47d6-9ba2-6d9d1ea9eb9a)

---

### **Support and Feedback**

For assistance, feature requests, or to report bugs, please contact me at:

- **Email:** [Sgt.Dicks+github@gmail.com](mailto:Sgt.Dicks+github@gmail.com)
