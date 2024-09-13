#!/usr/bin/env python3
import sys
import logging
from typing import Any, Dict, Optional, List
import requests
from requests import Session
import urllib3
import json
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from argparse import ArgumentParser, Namespace

# Disable only the specific InsecureRequestWarning from urllib3
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    filename='api_client_gui.log',
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

class APIClient:
    def __init__(self, host: str, port: int = 7777, verify_ssl: bool = False, auth_token: Optional[str] = None):
        self.host = host
        self.port = port
        self.verify_ssl = verify_ssl
        self.auth_token = auth_token
        self.base_url = f"https://{self.host}:{self.port}/api/v1"
        self.session: Session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update({
            "Content-Type": "application/json"
        })
        if self.auth_token:
            self.session.headers.update({
                "Authorization": f"Bearer {self.auth_token}"
            })
            logger.debug(f"Authorization header set with token: {self.auth_token}")
        logger.debug(f"Initialized APIClient with base URL: {self.base_url}")

    def post(self, function: str, data: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if data is None:
            data = {}
        payload = {
            "function": function,
            "data": data
        }
        logger.debug(f"POST Payload: {payload}")
        try:
            if files:
                logger.debug(f"Files to upload: {files.keys()}")
                response = self.session.post(self.base_url, data=json.dumps(payload), files=files, timeout=30)
            else:
                response = self.session.post(self.base_url, json=payload, timeout=10)
            logger.debug(f"Response Status Code: {response.status_code}")
            logger.debug(f"Response Headers: {response.headers}")
            if response.status_code in [200, 201, 202, 204]:
                if response.status_code == 204:
                    return {"message": "No Content"}
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    return response.json()
                elif 'application/octet-stream' in content_type or 'application/zip' in content_type:
                    # Handle file downloads
                    return {"file_content": response.content}
                else:
                    return {"raw_response": response.text}
            else:
                try:
                    error_response = response.json()
                    logger.error(f"Error Response: {error_response}")
                    return {"error": error_response}
                except ValueError:
                    logger.error(f"Non-JSON Error Response: {response.text}")
                    return {"error": {"errorMessage": response.text}}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise e
        except ValueError:
            logger.error("Failed to parse JSON response.")
            raise ValueError("Failed to parse JSON response.")

def query(client: APIClient, function: str, data: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if function == "HealthCheck":
        data = {"ClientCustomData": ""}
        logger.debug("Overriding data for HealthCheck function.")
    return client.post(function, data, files)

# Define available API functions and their parameters
API_FUNCTIONS = {
    "HealthCheck": {
        "requires_auth": False,
        "parameters": {
            "ClientCustomData": {"type": "string", "required": False, "default": ""}
        },
        "multipart": False
    },
    "VerifyAuthenticationToken": {
        "requires_auth": False,
        "parameters": {},
        "multipart": False
    },
    "PasswordlessLogin": {
        "requires_auth": False,
        "parameters": {
            "MinimumPrivilegeLevel": {"type": "enum", "options": ["NotAuthenticated", "Client", "Administrator", "InitialAdmin", "APIToken"], "required": True}
        },
        "multipart": False
    },
    "PasswordLogin": {
        "requires_auth": False,
        "parameters": {
            "MinimumPrivilegeLevel": {"type": "enum", "options": ["NotAuthenticated", "Client", "Administrator", "InitialAdmin", "APIToken"], "required": True},
            "Password": {"type": "password", "required": True}
        },
        "multipart": False
    },
    "QueryServerState": {
        "requires_auth": True,
        "parameters": {},
        "multipart": False
    },
    "GetServerOptions": {
        "requires_auth": True,
        "parameters": {},
        "multipart": False
    },
    "GetAdvancedGameSettings": {
        "requires_auth": True,
        "parameters": {},
        "multipart": False
    },
    "ApplyAdvancedGameSettings": {
        "requires_auth": True,
        "parameters": {
            "AppliedAdvancedGameSettings": {"type": "dict", "required": True}
        },
        "multipart": False
    },
    "ClaimServer": {
        "requires_auth": False,
        "parameters": {
            "ServerName": {"type": "string", "required": True},
            "AdminPassword": {"type": "password", "required": True}
        },
        "multipart": False
    },
    "RenameServer": {
        "requires_auth": True,
        "parameters": {
            "ServerName": {"type": "string", "required": True}
        },
        "multipart": False
    },
    "SetClientPassword": {
        "requires_auth": True,
        "parameters": {
            "Password": {"type": "password", "required": True}
        },
        "multipart": False
    },
    "SetAdminPassword": {
        "requires_auth": True,
        "parameters": {
            "Password": {"type": "password", "required": True},
            "AuthenticationToken": {"type": "string", "required": True}
        },
        "multipart": False
    },
    "SetAutoLoadSessionName": {
        "requires_auth": True,
        "parameters": {
            "SessionName": {"type": "string", "required": True}
        },
        "multipart": False
    },
    "RunCommand": {
        "requires_auth": True,
        "parameters": {
            "Command": {"type": "string", "required": True}
        },
        "multipart": False
    },
    "Shutdown": {
        "requires_auth": True,
        "parameters": {},
        "multipart": False
    },
    "ApplyServerOptions": {
        "requires_auth": True,
        "parameters": {
            "UpdatedServerOptions": {"type": "dict", "required": True}
        },
        "multipart": False
    },
    "CreateNewGame": {
        "requires_auth": True,
        "parameters": {
            "NewGameData": {
                "type": "dict",
                "required": True,
                "schema": {
                    "SessionName": {"type": "string", "required": True},
                    "MapName": {"type": "string", "required": False},
                    "StartingLocation": {"type": "string", "required": False},
                    "SkipOnboarding": {"type": "boolean", "required": False},
                    "AdvancedGameSettings": {"type": "dict", "required": False},
                    "CustomOptionsOnlyForModding": {"type": "dict", "required": False}
                }
            }
        },
        "multipart": False
    },
    "SaveGame": {
        "requires_auth": True,
        "parameters": {
            "SaveName": {"type": "string", "required": True}
        },
        "multipart": False
    },
    "DeleteSaveFile": {
        "requires_auth": True,
        "parameters": {
            "SaveName": {"type": "string", "required": True}
        },
        "multipart": False
    },
    "DeleteSaveSession": {
        "requires_auth": True,
        "parameters": {
            "SessionName": {"type": "string", "required": True}
        },
        "multipart": False
    },
    "EnumerateSessions": {
        "requires_auth": True,
        "parameters": {},
        "multipart": False
    },
    "LoadGame": {
        "requires_auth": True,
        "parameters": {
            "SaveName": {"type": "string", "required": True},
            "EnableAdvancedGameSettings": {"type": "boolean", "required": False}
        },
        "multipart": False
    },
    "UploadSaveGame": {
        "requires_auth": True,
        "parameters": {
            "SaveName": {"type": "string", "required": True},
            "LoadSaveGame": {"type": "boolean", "required": False},
            "EnableAdvancedGameSettings": {"type": "boolean", "required": False}
        },
        "multipart": True
    },
    "DownloadSaveGame": {
        "requires_auth": True,
        "parameters": {
            "SaveName": {"type": "string", "required": True}
        },
        "multipart": False  # Although it downloads files, it's a response handling case
    }
}

class APIClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Dedicated Server API Client")
        self.api_client: Optional[APIClient] = None
        self.auth_token: Optional[str] = None
        self.create_widgets()

    def create_widgets(self):
        # Host
        host_label = ttk.Label(self.root, text="Host:")
        host_label.grid(column=0, row=0, padx=5, pady=5, sticky=tk.W)
        self.host_entry = ttk.Entry(self.root, width=30)
        self.host_entry.grid(column=1, row=0, padx=5, pady=5, sticky=tk.W)
        self.host_entry.insert(0, "localhost")  # Default value

        # Port
        port_label = ttk.Label(self.root, text="Port:")
        port_label.grid(column=0, row=1, padx=5, pady=5, sticky=tk.W)
        self.port_entry = ttk.Entry(self.root, width=30)
        self.port_entry.grid(column=1, row=1, padx=5, pady=5, sticky=tk.W)
        self.port_entry.insert(0, "7777")  # Default value

        # Authentication Section
        auth_frame = ttk.LabelFrame(self.root, text="Authentication")
        auth_frame.grid(column=0, row=2, columnspan=2, padx=5, pady=5, sticky=tk.EW)

        # Authentication Method
        auth_method_label = ttk.Label(auth_frame, text="Method:")
        auth_method_label.grid(column=0, row=0, padx=5, pady=5, sticky=tk.W)
        self.auth_method_var = tk.StringVar()
        self.auth_method_dropdown = ttk.Combobox(
            auth_frame,
            textvariable=self.auth_method_var,
            values=["Bearer Token", "Passwordless Login", "Password Login"],
            state="readonly",
            width=25
        )
        self.auth_method_dropdown.grid(column=1, row=0, padx=5, pady=5, sticky=tk.W)
        self.auth_method_dropdown.set("Bearer Token")  # Default

        # Bearer Token Entry
        self.bearer_frame = ttk.Frame(auth_frame)
        self.bearer_frame.grid(column=0, row=1, columnspan=2, padx=5, pady=5, sticky=tk.EW)
        bearer_label = ttk.Label(self.bearer_frame, text="Bearer Token:")
        bearer_label.grid(column=0, row=0, padx=5, pady=5, sticky=tk.W)
        self.bearer_entry = ttk.Entry(self.bearer_frame, width=50)
        self.bearer_entry.grid(column=1, row=0, padx=5, pady=5, sticky=tk.W)

        # Passwordless Login Frame
        self.passwordless_frame = ttk.Frame(auth_frame)
        # Initially hidden
        self.passwordless_frame.grid_remove()
        min_priv_label = ttk.Label(self.passwordless_frame, text="Minimum Privilege Level:")
        min_priv_label.grid(column=0, row=0, padx=5, pady=5, sticky=tk.W)
        self.min_priv_var = tk.StringVar()
        self.min_priv_dropdown = ttk.Combobox(
            self.passwordless_frame,
            textvariable=self.min_priv_var,
            values=["Client", "Administrator", "InitialAdmin", "APIToken"],
            state="readonly",
            width=25
        )
        self.min_priv_dropdown.grid(column=1, row=0, padx=5, pady=5, sticky=tk.W)
        self.min_priv_dropdown.set("Client")  # Default

        # Password Login Frame
        self.password_login_frame = ttk.Frame(auth_frame)
        # Initially hidden
        self.password_login_frame.grid_remove()
        self.min_priv_login_label = ttk.Label(self.password_login_frame, text="Minimum Privilege Level:")
        self.min_priv_login_label.grid(column=0, row=0, padx=5, pady=5, sticky=tk.W)
        self.min_priv_login_var = tk.StringVar()
        self.min_priv_login_dropdown = ttk.Combobox(
            self.password_login_frame,
            textvariable=self.min_priv_login_var,
            values=["Client", "Administrator", "InitialAdmin", "APIToken"],
            state="readonly",
            width=25
        )
        self.min_priv_login_dropdown.grid(column=1, row=0, padx=5, pady=5, sticky=tk.W)
        self.min_priv_login_dropdown.set("Client")  # Default
        self.password_label = ttk.Label(self.password_login_frame, text="Password:")
        self.password_label.grid(column=0, row=1, padx=5, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(self.password_login_frame, width=30, show="*")
        self.password_entry.grid(column=1, row=1, padx=5, pady=5, sticky=tk.W)

        # Bind authentication method change
        self.auth_method_dropdown.bind("<<ComboboxSelected>>", self.update_auth_fields)

        # Authenticate Button
        auth_button = ttk.Button(auth_frame, text="Authenticate", command=self.authenticate)
        auth_button.grid(column=2, row=0, padx=5, pady=5, sticky=tk.E)

        # Function Selection
        function_label = ttk.Label(self.root, text="Function:")
        function_label.grid(column=0, row=3, padx=5, pady=5, sticky=tk.W)
        self.function_var = tk.StringVar()
        self.function_dropdown = ttk.Combobox(
            self.root,
            textvariable=self.function_var,
            values=list(API_FUNCTIONS.keys()),
            state="readonly",
            width=30
        )
        self.function_dropdown.grid(column=1, row=3, padx=5, pady=5, sticky=tk.W)
        self.function_dropdown.bind("<<ComboboxSelected>>", self.update_parameter_fields)

        # Parameters Frame
        self.params_frame = ttk.LabelFrame(self.root, text="Parameters")
        self.params_frame.grid(column=0, row=4, columnspan=2, padx=5, pady=5, sticky=tk.EW)

        # Dynamic parameter widgets will be added here
        self.param_widgets: Dict[str, Any] = {}

        # File Selection (for Upload/Download)
        self.file_frame = ttk.Frame(self.root)
        self.file_frame.grid(column=0, row=5, columnspan=2, padx=5, pady=5, sticky=tk.EW)
        self.file_path_var = tk.StringVar()
        self.file_button = ttk.Button(self.file_frame, text="Select File", command=self.select_file)
        self.file_button.grid(column=0, row=0, padx=5, pady=5, sticky=tk.W)
        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.file_path_var, width=50, state='readonly')
        self.file_entry.grid(column=1, row=0, padx=5, pady=5, sticky=tk.W)

        # Send Button
        send_button = ttk.Button(self.root, text="Send Request", command=self.send_request)
        send_button.grid(column=1, row=6, padx=5, pady=10, sticky=tk.E)

        # Response
        response_label = ttk.Label(self.root, text="Response:")
        response_label.grid(column=0, row=7, padx=5, pady=5, sticky=tk.NW)
        self.response_text = scrolledtext.ScrolledText(self.root, width=80, height=20, state='disabled')
        self.response_text.grid(column=0, row=8, columnspan=2, padx=5, pady=5, sticky=tk.W)

    def update_auth_fields(self, event):
        method = self.auth_method_var.get()
        logger.debug(f"Selected Authentication Method: {method}")
        # Hide all auth frames first
        self.bearer_frame.grid_remove()
        self.passwordless_frame.grid_remove()
        self.password_login_frame.grid_remove()

        if method == "Bearer Token":
            self.bearer_frame.grid()
        elif method == "Passwordless Login":
            self.passwordless_frame.grid()
        elif method == "Password Login":
            self.password_login_frame.grid()

    def authenticate(self):
        method = self.auth_method_var.get()
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip()

        if not host:
            messagebox.showerror("Input Error", "Host is required.")
            return
        if not port.isdigit():
            messagebox.showerror("Input Error", "Port must be a number.")
            return
        port = int(port)

        if method == "Bearer Token":
            token = self.bearer_entry.get().strip()
            if not token:
                messagebox.showerror("Input Error", "Bearer Token is required.")
                return
            self.auth_token = token
            self.api_client = APIClient(host=host, port=port, verify_ssl=False, auth_token=self.auth_token)
            messagebox.showinfo("Authentication", "Bearer Token authentication successful.")
            logger.info("Authenticated using Bearer Token.")
        elif method == "Passwordless Login":
            min_priv = self.min_priv_var.get()
            if not min_priv:
                messagebox.showerror("Input Error", "Minimum Privilege Level is required.")
                return
            data = {"MinimumPrivilegeLevel": min_priv}
            try:
                temp_client = APIClient(host=host, port=port, verify_ssl=False)
                response = query(temp_client, "PasswordlessLogin", data)
                logger.debug(f"PasswordlessLogin Response: {response}")
                if "AuthenticationToken" in response:
                    self.auth_token = response["AuthenticationToken"]
                    self.api_client = APIClient(host=host, port=port, verify_ssl=False, auth_token=self.auth_token)
                    messagebox.showinfo("Authentication", "Passwordless Login successful.")
                    logger.info("Authenticated using Passwordless Login.")
                elif "error" in response:
                    error = response["error"]
                    messagebox.showerror("Authentication Error", f"{error.get('errorMessage', 'Unknown error')}")
                    logger.error(f"Authentication Error: {error.get('errorMessage', 'Unknown error')}")
            except Exception as e:
                messagebox.showerror("Authentication Error", f"Failed to authenticate: {e}")
                logger.error(f"Authentication Exception: {e}")
        elif method == "Password Login":
            min_priv = self.min_priv_login_var.get()
            password = self.password_entry.get().strip()
            if not min_priv:
                messagebox.showerror("Input Error", "Minimum Privilege Level is required.")
                return
            if not password:
                messagebox.showerror("Input Error", "Password is required.")
                return
            data = {
                "MinimumPrivilegeLevel": min_priv,
                "Password": password
            }
            try:
                temp_client = APIClient(host=host, port=port, verify_ssl=False)
                response = query(temp_client, "PasswordLogin", data)
                logger.debug(f"PasswordLogin Response: {response}")
                if "AuthenticationToken" in response:
                    self.auth_token = response["AuthenticationToken"]
                    self.api_client = APIClient(host=host, port=port, verify_ssl=False, auth_token=self.auth_token)
                    messagebox.showinfo("Authentication", "Password Login successful.")
                    logger.info("Authenticated using Password Login.")
                elif "error" in response:
                    error = response["error"]
                    messagebox.showerror("Authentication Error", f"{error.get('errorMessage', 'Unknown error')}")
                    logger.error(f"Authentication Error: {error.get('errorMessage', 'Unknown error')}")
            except Exception as e:
                messagebox.showerror("Authentication Error", f"Failed to authenticate: {e}")
                logger.error(f"Authentication Exception: {e}")

    def update_parameter_fields(self, event):
        selected_function = self.function_var.get()
        logger.debug(f"Selected Function: {selected_function}")
        # Clear existing parameter widgets
        for widget in self.params_frame.winfo_children():
            widget.destroy()
        self.param_widgets.clear()

        if not selected_function:
            return

        func_info = API_FUNCTIONS.get(selected_function, {})
        parameters = func_info.get("parameters", {})
        row = 0

        for param_name, param_details in parameters.items():
            label = ttk.Label(self.params_frame, text=f"{param_name}:")
            label.grid(column=0, row=row, padx=5, pady=5, sticky=tk.W)
            if param_details["type"] == "string":
                entry = ttk.Entry(self.params_frame, width=50)
                entry.grid(column=1, row=row, padx=5, pady=5, sticky=tk.W)
            elif param_details["type"] == "password":
                entry = ttk.Entry(self.params_frame, width=50, show="*")
                entry.grid(column=1, row=row, padx=5, pady=5, sticky=tk.W)
            elif param_details["type"] == "enum":
                entry = ttk.Combobox(
                    self.params_frame,
                    values=param_details["options"],
                    state="readonly",
                    width=48
                )
                entry.grid(column=1, row=row, padx=5, pady=5, sticky=tk.W)
                if "default" in param_details:
                    entry.set(param_details["default"])
                else:
                    entry.set(param_details["options"][0])
            elif param_details["type"] == "boolean":
                var = tk.BooleanVar()
                entry = ttk.Checkbutton(self.params_frame, variable=var)
                entry.var = var  # Attach variable to widget
                entry.grid(column=1, row=row, padx=5, pady=5, sticky=tk.W)
            elif param_details["type"] == "dict":
                entry = scrolledtext.ScrolledText(self.params_frame, width=50, height=5)
                entry.grid(column=1, row=row, padx=5, pady=5, sticky=tk.W)
            elif param_details["type"] == "integer":
                entry = ttk.Entry(self.params_frame, width=50)
                entry.grid(column=1, row=row, padx=5, pady=5, sticky=tk.W)
            else:
                entry = ttk.Entry(self.params_frame, width=50)
                entry.grid(column=1, row=row, padx=5, pady=5, sticky=tk.W)

            # Set default value if available
            if "default" in param_details:
                if param_details["type"] == "boolean":
                    entry.var.set(param_details["default"])
                elif param_details["type"] == "dict":
                    entry.insert(tk.END, json.dumps(param_details["default"], indent=4))
                else:
                    entry.insert(0, param_details["default"])

            self.param_widgets[param_name] = entry
            row += 1

        # Handle multipart functions
        if func_info.get("multipart", False):
            self.file_frame.grid()
        else:
            self.file_frame.grid_remove()

    def select_file(self):
        selected_function = self.function_var.get()
        if selected_function == "UploadSaveGame":
            file_path = filedialog.askopenfilename(title="Select Save Game File")
            if file_path:
                self.file_path_var.set(file_path)
        elif selected_function == "DownloadSaveGame":
            # Choose where to save the downloaded file
            file_path = filedialog.asksaveasfilename(title="Save Save Game File As")
            if file_path:
                self.file_path_var.set(file_path)

    def send_request(self):
        if not self.api_client:
            messagebox.showerror("Authentication Error", "Please authenticate first.")
            return

        selected_function = self.function_var.get()
        if not selected_function:
            messagebox.showerror("Input Error", "Please select a function.")
            return

        func_info = API_FUNCTIONS.get(selected_function, {})
        requires_auth = func_info.get("requires_auth", False)
        parameters = func_info.get("parameters", {})
        multipart = func_info.get("multipart", False)

        data = {}
        files = None

        # Gather parameters
        for param_name, param_details in parameters.items():
            widget = self.param_widgets.get(param_name)
            if not widget:
                continue
            if param_details["type"] == "string" or param_details["type"] == "password":
                value = widget.get().strip()
                if param_details.get("required", False) and not value:
                    messagebox.showerror("Input Error", f"{param_name} is required.")
                    return
                data[param_name] = value
            elif param_details["type"] == "enum":
                value = widget.get().strip()
                if param_details.get("required", False) and not value:
                    messagebox.showerror("Input Error", f"{param_name} is required.")
                    return
                data[param_name] = value
            elif param_details["type"] == "boolean":
                var = getattr(widget, 'var', None)
                value = var.get() if var else False
                data[param_name] = value
            elif param_details["type"] == "dict":
                text_content = widget.get("1.0", tk.END).strip()
                if param_details.get("required", False) and not text_content:
                    messagebox.showerror("Input Error", f"{param_name} is required.")
                    return
                try:
                    data[param_name] = json.loads(text_content) if text_content else {}
                except json.JSONDecodeError as e:
                    messagebox.showerror("Input Error", f"Invalid JSON for {param_name}:\n{e}")
                    return
            elif param_details["type"] == "integer":
                value = widget.get().strip()
                if param_details.get("required", False) and not value:
                    messagebox.showerror("Input Error", f"{param_name} is required.")
                    return
                try:
                    data[param_name] = int(value) if value else 0
                except ValueError:
                    messagebox.showerror("Input Error", f"{param_name} must be an integer.")
                    return
            else:
                value = widget.get().strip()
                if param_details.get("required", False) and not value:
                    messagebox.showerror("Input Error", f"{param_name} is required.")
                    return
                data[param_name] = value

        # Handle multipart
        if multipart:
            file_path = self.file_path_var.get().strip()
            if not file_path:
                messagebox.showerror("Input Error", "Please select a file for multipart request.")
                return
            try:
                files = {
                    'saveGameFile': open(file_path, 'rb')
                }
                # For 'data' part in multipart
                files['data'] = ('data', json.dumps(data), 'application/json')
            except Exception as e:
                messagebox.showerror("File Error", f"Failed to open file: {e}")
                return

        # Special handling for DownloadSaveGame to specify download path
        if selected_function == "DownloadSaveGame":
            file_save_path = self.file_path_var.get().strip()
            if not file_save_path:
                messagebox.showerror("Input Error", "Please select a save location for the downloaded file.")
                return

        # Send request
        try:
            response = query(self.api_client, selected_function, data, files)
            if files:
                # Close the file
                for key, file in files.items():
                    if key != 'data' and hasattr(file, 'close'):
                        file.close()

            if "error" in response:
                error = response["error"]
                error_message = error.get('errorMessage', 'Unknown error')
                messagebox.showerror("API Error", f"{error_message}")
                self.display_response(json.dumps(error, indent=4))
                logger.error(f"API Error: {error_message}")
            else:
                if selected_function == "DownloadSaveGame" and "file_content" in response:
                    with open(file_save_path, 'wb') as f:
                        f.write(response["file_content"])
                    messagebox.showinfo("Download Successful", f"Save game downloaded to {file_save_path}")
                    self.display_response("File downloaded successfully.")
                elif multipart and "file_content" in response:
                    # Handle other multipart responses if any
                    self.display_response("Multipart response received.")
                else:
                    self.display_response(json.dumps(response, indent=4))
                    if selected_function in ["PasswordLogin", "PasswordlessLogin"] and "AuthenticationToken" in response:
                        # Update auth token if these functions return a new token
                        self.auth_token = response["AuthenticationToken"]
                        self.api_client = APIClient(
                            host=self.api_client.host,
                            port=self.api_client.port,
                            verify_ssl=self.api_client.session.verify,
                            auth_token=self.auth_token
                        )
                        messagebox.showinfo("Authentication", "Authentication token updated successfully.")
            logger.info(f"Function {selected_function} executed successfully.")
        except Exception as e:
            messagebox.showerror("Request Error", f"Failed to send request: {e}")
            self.display_response(f"Request failed: {e}")
            logger.error(f"Function {selected_function} failed: {e}")

    def display_response(self, response):
        self.response_text.config(state='normal')
        self.response_text.delete("1.0", tk.END)
        if isinstance(response, str):
            self.response_text.insert(tk.END, response)
        elif isinstance(response, dict):
            formatted_response = json.dumps(response, indent=4)
            self.response_text.insert(tk.END, formatted_response)
        else:
            self.response_text.insert(tk.END, str(response))
        self.response_text.config(state='disabled')

def main():
    root = tk.Tk()
    app = APIClientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

