import socket
import threading
import os
import json
from datetime import datetime
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, LEFT, W, E, BOTH, END
from tkinter import scrolledtext
import tkinter as tk

class ProfessionalChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("📱 Enterprise Chat Client")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        self.root.resizable(True, True)
        
        # Application state
        self.socket = None
        self.username = ""
        self.connected = False
        self.user_colors = {}
        self.color_palette = [
            "#3498db", "#e74c3c", "#2ecc71", "#f39c12", "#9b59b6", 
            "#1abc9c", "#e67e22", "#34495e", "#e91e63", "#00bcd4"
        ]
        self.color_index = 0
        
        # Setup UI
        self.setup_styles()
        self.build_ui()
        
        # Bind events
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def setup_styles(self):
        """Configure custom styles for professional look"""
        style = ttk.Style()
        
        # Custom button styles
        style.configure("Connect.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Send.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Disconnect.TButton", font=("Segoe UI", 10, "bold"))
        
        # Custom label styles
        style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 9))
        
    def build_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=BOTH, expand=True)
        
        # Configure main grid
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Top panel for connection
        self.build_connection_panel(main_frame)
        
        # Main chat area
        self.build_chat_area(main_frame)
        
        # Bottom panel for input
        self.build_input_panel(main_frame)
        
        # Status bar
        self.build_status_bar(main_frame)
        
    def build_connection_panel(self, parent):
        """Build the connection configuration panel"""
        conn_frame = ttk.LabelFrame(parent, text="🔗 Connection Settings", padding=15)
        conn_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        # Configure grid
        conn_frame.columnconfigure(1, weight=1)
        conn_frame.columnconfigure(3, weight=1)
        conn_frame.columnconfigure(5, weight=1)
        
        # Server IP
        ttk.Label(conn_frame, text="Server IP:", font=("Segoe UI", 10)).grid(row=0, column=0, sticky=W, padx=(0, 5))
        self.ip_entry = ttk.Entry(conn_frame, width=15, font=("Segoe UI", 10))
        self.ip_entry.grid(row=0, column=1, sticky="ew", padx=(0, 15))
        self.ip_entry.insert(0, "127.0.0.1")
        
        # Server Port
        ttk.Label(conn_frame, text="Port:", font=("Segoe UI", 10)).grid(row=0, column=2, sticky=W, padx=(0, 5))
        self.port_entry = ttk.Entry(conn_frame, width=10, font=("Segoe UI", 10))
        self.port_entry.grid(row=0, column=3, sticky="ew", padx=(0, 15))
        self.port_entry.insert(0, "5000")
        
        # Username
        ttk.Label(conn_frame, text="Username:", font=("Segoe UI", 10)).grid(row=0, column=4, sticky=W, padx=(0, 5))
        self.username_entry = ttk.Entry(conn_frame, width=15, font=("Segoe UI", 10))
        self.username_entry.grid(row=0, column=5, sticky="ew", padx=(0, 15))
        
        # Connect/Disconnect buttons
        button_frame = ttk.Frame(conn_frame)
        button_frame.grid(row=0, column=6, sticky="e")
        
        self.connect_btn = ttk.Button(button_frame, text="🔌 Connect", 
                                     bootstyle="success", style="Connect.TButton",
                                     command=self.connect_to_server)
        self.connect_btn.pack(side=LEFT, padx=(0, 5))
        
        self.disconnect_btn = ttk.Button(button_frame, text="🔌 Disconnect", 
                                        bootstyle="danger", style="Disconnect.TButton",
                                        command=self.disconnect_from_server, state=DISABLED)
        self.disconnect_btn.pack(side=LEFT)
        
        # Bind Enter key to connect
        self.root.bind('<Return>', lambda e: self.connect_to_server() if not self.connected else None)
        
    def build_chat_area(self, parent):
        """Build the main chat display area"""
        chat_frame = ttk.LabelFrame(parent, text="💬 Chat Messages", padding=10)
        chat_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        
        # Configure grid
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)
        
        # Chat display with scrollbar
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, 
            wrap=tk.WORD, 
            font=("Segoe UI", 10),
            bg="#f8f9fa",
            fg="#212529",
            selectbackground="#007bff",
            selectforeground="white",
            state=DISABLED,
            height=20
        )
        self.chat_display.grid(row=0, column=0, sticky="nsew")
        
        # Configure text tags for different message types
        self.chat_display.tag_configure("timestamp", foreground="#6c757d", font=("Segoe UI", 8))
        self.chat_display.tag_configure("system", foreground="#28a745", font=("Segoe UI", 10, "bold"))
        self.chat_display.tag_configure("error", foreground="#dc3545", font=("Segoe UI", 10, "bold"))
        self.chat_display.tag_configure("file", foreground="#17a2b8", font=("Segoe UI", 10, "italic"))
        self.chat_display.tag_configure("own_message", foreground="#007bff", font=("Segoe UI", 10, "bold"))
        
    def build_input_panel(self, parent):
        """Build the message input panel"""
        input_frame = ttk.LabelFrame(parent, text="✍️ Send Message", padding=10)
        input_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        
        # Configure grid
        input_frame.columnconfigure(0, weight=1)
        
        # Message type selection
        type_frame = ttk.Frame(input_frame)
        type_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        ttk.Label(type_frame, text="Type:", font=("Segoe UI", 10)).pack(side=LEFT, padx=(0, 10))
        
        self.message_type = ttk.StringVar(value="message")
        type_radio_frame = ttk.Frame(type_frame)
        type_radio_frame.pack(side=LEFT)
        
        ttk.Radiobutton(type_radio_frame, text="💬 Message", variable=self.message_type, 
                       value="message", command=self.toggle_input_type).pack(side=LEFT, padx=(0, 15))
        ttk.Radiobutton(type_radio_frame, text="📁 File", variable=self.message_type, 
                       value="file", command=self.toggle_input_type).pack(side=LEFT)
        
        # Message input area
        self.message_frame = ttk.Frame(input_frame)
        self.message_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        self.message_frame.columnconfigure(0, weight=1)
        
        # Text message input
        self.message_entry = ttk.Entry(self.message_frame, font=("Segoe UI", 10))
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        # File input (initially hidden)
        self.file_frame = ttk.Frame(input_frame)
        self.file_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        self.file_frame.columnconfigure(0, weight=1)
        
        self.file_path_entry = ttk.Entry(self.file_frame, font=("Segoe UI", 10))
        self.file_path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        
        ttk.Button(self.file_frame, text="📂 Browse", bootstyle="secondary",
                  command=self.browse_file).grid(row=0, column=1, padx=(0, 10))
        
        # Send button
        self.send_btn = ttk.Button(input_frame, text="📤 Send", bootstyle="primary",
                                  style="Send.TButton", command=self.send_message, state=DISABLED)
        self.send_btn.grid(row=3, column=0, pady=(10, 0))
        
        # Initially hide file frame
        self.file_frame.grid_remove()
        
    def build_status_bar(self, parent):
        """Build the status bar"""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=3, column=0, sticky="ew")
        
        # Status label
        self.status_label = ttk.Label(status_frame, text="❌ Disconnected", 
                                     style="Status.TLabel", foreground="#dc3545")
        self.status_label.pack(side=LEFT)
        
        # Online users count (placeholder for future enhancement)
        self.users_label = ttk.Label(status_frame, text="👥 Users: 0", 
                                    style="Status.TLabel")
        self.users_label.pack(side=RIGHT)
        
    def toggle_input_type(self):
        """Toggle between message and file input"""
        if self.message_type.get() == "message":
            self.file_frame.grid_remove()
            self.message_frame.grid()
            self.message_entry.focus()
        else:
            self.message_frame.grid_remove()
            self.file_frame.grid()
            self.file_path_entry.focus()
            
    def browse_file(self):
        """Open file dialog to select file"""
        file_path = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[
                ("All files", "*.*"),
                ("Text files", "*.txt"),
                ("Images", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("Documents", "*.pdf *.doc *.docx")
            ]
        )
        if file_path:
            self.file_path_entry.delete(0, END)
            self.file_path_entry.insert(0, file_path)
            
    def connect_to_server(self):
        """Connect to the chat server"""
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()
        username = self.username_entry.get().strip()
        
        if not ip or not port or not username:
            messagebox.showerror("❌ Connection Error", "Please fill in all connection fields.")
            return
            
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("❌ Connection Error", "Port must be a valid number.")
            return
            
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)  # 10 second timeout
            self.socket.connect((ip, port))
            
            # Send username
            self.socket.sendall(username.encode('utf-8'))
            
            # Update UI state
            self.connected = True
            self.username = username
            self.connect_btn.config(state=DISABLED)
            self.disconnect_btn.config(state=NORMAL)
            self.send_btn.config(state=NORMAL)
            
            # Disable connection fields
            self.ip_entry.config(state=DISABLED)
            self.port_entry.config(state=DISABLED)
            self.username_entry.config(state=DISABLED)
            
            # Update status
            self.status_label.config(text=f"✅ Connected to {ip}:{port}", foreground="#28a745")
            
            # Add system message
            self.add_system_message(f"Connected to server as {username}")
            
            # Start receiving messages
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
            
        except socket.timeout:
            messagebox.showerror("❌ Connection Error", "Connection timeout. Please check server address.")
            if self.socket:
                self.socket.close()
        except Exception as e:
            messagebox.showerror("❌ Connection Error", f"Failed to connect: {str(e)}")
            if self.socket:
                self.socket.close()
                
    def disconnect_from_server(self):
        """Disconnect from the chat server"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
            
        # Update UI state
        self.connected = False
        self.connect_btn.config(state=NORMAL)
        self.disconnect_btn.config(state=DISABLED)
        self.send_btn.config(state=DISABLED)
        
        # Enable connection fields
        self.ip_entry.config(state=NORMAL)
        self.port_entry.config(state=NORMAL)
        self.username_entry.config(state=NORMAL)
        
        # Update status
        self.status_label.config(text="❌ Disconnected", foreground="#dc3545")
        
        # Add system message
        self.add_system_message("Disconnected from server")
        
    def receive_messages(self):
        """Receive messages from server in a separate thread"""
        try:
            while self.connected and self.socket:
                try:
                    data = self.socket.recv(1024)
                    if not data:
                        break
                        
                    message = data.decode('utf-8')
                    self.root.after(0, self.handle_received_message, message)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.connected:
                        self.root.after(0, self.add_error_message, f"Error receiving message: {str(e)}")
                    break
                    
        except Exception as e:
            if self.connected:
                self.root.after(0, self.add_error_message, f"Connection error: {str(e)}")
        finally:
            if self.connected:
                self.root.after(0, self.disconnect_from_server)
                
    def handle_received_message(self, message):
        """Handle received message from server"""
        # This is a placeholder - in a real implementation, 
        # the server would send structured data about messages
        self.add_chat_message("Server", message)
        
    def send_message(self):
        """Send message or file to server"""
        if not self.connected:
            messagebox.showwarning("⚠️ Warning", "Not connected to server.")
            return
            
        try:
            if self.message_type.get() == "message":
                message = self.message_entry.get().strip()
                if not message:
                    messagebox.showwarning("⚠️ Warning", "Message cannot be empty.")
                    return
                    
                # Send message
                self.socket.sendall(b'm')
                self.socket.sendall(message.encode('utf-8'))
                
                # Add to chat display
                self.add_chat_message(self.username, message, is_own=True)
                
                # Clear input
                self.message_entry.delete(0, END)
                
            else:  # file
                file_path = self.file_path_entry.get().strip()
                if not file_path or not os.path.isfile(file_path):
                    messagebox.showerror("❌ Error", "Please select a valid file.")
                    return
                    
                filename = os.path.basename(file_path)
                
                # Send file
                self.socket.sendall(b'f')
                self.socket.sendall(f"file:{filename}".encode('utf-8'))
                
                with open(file_path, "rb") as f:
                    while True:
                        data = f.read(1024)
                        if not data:
                            break
                        self.socket.sendall(data)
                    self.socket.sendall(b"FILE_TRANSMISSION_COMPLETE")
                    
                # Add to chat display
                self.add_file_message(self.username, filename, is_own=True)
                
                # Clear input
                self.file_path_entry.delete(0, END)
                
        except Exception as e:
            messagebox.showerror("❌ Send Error", f"Failed to send: {str(e)}")
            
    def get_user_color(self, username):
        """Get or assign a color for a user"""
        if username not in self.user_colors:
            self.user_colors[username] = self.color_palette[self.color_index % len(self.color_palette)]
            self.color_index += 1
        return self.user_colors[username]
        
    def add_chat_message(self, username, message, is_own=False):
        """Add a chat message to the display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.chat_display.config(state=NORMAL)
        
        # Add timestamp
        self.chat_display.insert(END, f"[{timestamp}] ", "timestamp")
        
        # Add username with color
        if is_own:
            self.chat_display.insert(END, f"{username}: ", "own_message")
        else:
            color = self.get_user_color(username)
            tag_name = f"user_{username}"
            self.chat_display.tag_configure(tag_name, foreground=color, font=("Segoe UI", 10, "bold"))
            self.chat_display.insert(END, f"{username}: ", tag_name)
        
        # Add message
        self.chat_display.insert(END, f"{message}\n")
        
        self.chat_display.config(state=DISABLED)
        self.chat_display.see(END)
        
    def add_file_message(self, username, filename, is_own=False):
        """Add a file message to the display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.chat_display.config(state=NORMAL)
        
        # Add timestamp
        self.chat_display.insert(END, f"[{timestamp}] ", "timestamp")
        
        # Add username with color
        if is_own:
            self.chat_display.insert(END, f"{username}: ", "own_message")
        else:
            color = self.get_user_color(username)
            tag_name = f"user_{username}"
            self.chat_display.tag_configure(tag_name, foreground=color, font=("Segoe UI", 10, "bold"))
            self.chat_display.insert(END, f"{username}: ", tag_name)
        
        # Add file info
        self.chat_display.insert(END, f"📁 Sent file: {filename}\n", "file")
        
        self.chat_display.config(state=DISABLED)
        self.chat_display.see(END)
        
    def add_system_message(self, message):
        """Add a system message to the display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.chat_display.config(state=NORMAL)
        self.chat_display.insert(END, f"[{timestamp}] ", "timestamp")
        self.chat_display.insert(END, f"🔧 SYSTEM: {message}\n", "system")
        self.chat_display.config(state=DISABLED)
        self.chat_display.see(END)
        
    def add_error_message(self, message):
        """Add an error message to the display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.chat_display.config(state=NORMAL)
        self.chat_display.insert(END, f"[{timestamp}] ", "timestamp")
        self.chat_display.insert(END, f"❌ ERROR: {message}\n", "error")
        self.chat_display.config(state=DISABLED)
        self.chat_display.see(END)
        
    def on_closing(self):
        """Handle application closing"""
        if self.connected:
            self.disconnect_from_server()
        self.root.destroy()


if __name__ == "__main__":
    root = ttk.Window(themename="cosmo")
    app = ProfessionalChatClient(root)
    root.mainloop()