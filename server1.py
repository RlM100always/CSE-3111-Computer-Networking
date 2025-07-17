import socket
import threading
import sys
import os
import json
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import ttkbootstrap as ttk
from ttkbootstrap import ttk as ttk_widgets

class ProfessionalChatServer:
    def __init__(self, root):
        self.root = root
        self.root.title("🖥️ Enterprise Chat Server")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)
        self.root.resizable(True, True)
        
        # Server state
        self.server_socket = None
        self.is_running = False
        self.clients = {}  # {socket: {'username': str, 'address': tuple, 'thread': thread}}
        self.client_lock = threading.Lock()
        
        # Message queue for thread-safe GUI updates
        self.message_queue = queue.Queue()
        
        # Setup UI
        self.setup_styles()
        self.build_ui()
        
        # Start message processing
        self.process_messages()
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def setup_styles(self):
        """Setup professional styling"""
        style = ttk.Style()
        
        # Configure styles
        style.configure("Server.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 10))
        style.configure("Info.TLabel", font=("Segoe UI", 9))
        
    def build_ui(self):
        """Build the main UI"""
        # Main container
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid
        main_frame.columnconfigure(0, weight=2)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Top panel
        self.build_top_panel(main_frame)
        
        # Main content area
        self.build_main_content(main_frame)
        
        # Bottom status bar
        self.build_status_bar(main_frame)
        
    def build_top_panel(self, parent):
        """Build the top control panel"""
        top_frame = ttk.Frame(parent)
        top_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        # Title
        title_label = ttk.Label(top_frame, text="🖥️ Enterprise Chat Server", 
                               style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        
        # Control buttons
        button_frame = ttk.Frame(top_frame)
        button_frame.pack(side=tk.RIGHT)
        
        # Server configuration
        config_frame = ttk.Frame(button_frame)
        config_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Label(config_frame, text="Port:", font=("Segoe UI", 10)).pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="5000")
        port_entry = ttk.Entry(config_frame, textvariable=self.port_var, width=8)
        port_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # Start/Stop buttons
        self.start_btn = ttk.Button(button_frame, text="🚀 Start Server", 
                                   bootstyle="success", style="Server.TButton",
                                   command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_btn = ttk.Button(button_frame, text="⏹️ Stop Server", 
                                  bootstyle="danger", style="Server.TButton",
                                  command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Clear logs button
        ttk.Button(button_frame, text="🗑️ Clear Logs", 
                  bootstyle="secondary", style="Server.TButton",
                  command=self.clear_logs).pack(side=tk.LEFT)
        
    def build_main_content(self, parent):
        """Build the main content area"""
        # Left panel - Server logs
        left_frame = ttk.LabelFrame(parent, text="📋 Server Logs", padding=10)
        left_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        
        # Configure grid
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(0, weight=1)
        
        # Log display
        self.log_display = scrolledtext.ScrolledText(
            left_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="#ffffff",
            selectbackground="#264f78",
            selectforeground="white",
            state=tk.DISABLED
        )
        self.log_display.grid(row=0, column=0, sticky="nsew")
        
        # Configure log tags
        self.log_display.tag_configure("timestamp", foreground="#808080")
        self.log_display.tag_configure("info", foreground="#4fc3f7")
        self.log_display.tag_configure("success", foreground="#66bb6a")
        self.log_display.tag_configure("warning", foreground="#ffb74d")
        self.log_display.tag_configure("error", foreground="#f44336")
        self.log_display.tag_configure("client", foreground="#ab47bc")
        self.log_display.tag_configure("message", foreground="#26c6da")
        self.log_display.tag_configure("file", foreground="#ffa726")
        
        # Right panel - Client management
        right_frame = ttk.LabelFrame(parent, text="👥 Connected Clients", padding=10)
        right_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 0))
        
        # Configure grid
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)
        
        # Client info header
        info_frame = ttk.Frame(right_frame)
        info_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.client_count_label = ttk.Label(info_frame, text="👥 Connected: 0", 
                                          style="Info.TLabel")
        self.client_count_label.pack(side=tk.LEFT)
        
        # Client list
        self.client_tree = ttk.Treeview(right_frame, columns=("username", "address", "connected"), 
                                       show="tree headings", height=10)
        self.client_tree.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        
        # Configure columns
        self.client_tree.heading("#0", text="ID")
        self.client_tree.heading("username", text="Username")
        self.client_tree.heading("address", text="IP Address")
        self.client_tree.heading("connected", text="Connected At")
        
        self.client_tree.column("#0", width=50)
        self.client_tree.column("username", width=100)
        self.client_tree.column("address", width=100)
        self.client_tree.column("connected", width=120)
        
        # Scrollbar for client list
        client_scrollbar = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.client_tree.yview)
        client_scrollbar.grid(row=1, column=1, sticky="ns")
        self.client_tree.configure(yscrollcommand=client_scrollbar.set)
        
        # Client management buttons
        client_btn_frame = ttk.Frame(right_frame)
        client_btn_frame.grid(row=2, column=0, sticky="ew")
        
        ttk.Button(client_btn_frame, text="🔄 Refresh", 
                  bootstyle="info", command=self.refresh_clients).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(client_btn_frame, text="⚠️ Kick Client", 
                  bootstyle="warning", command=self.kick_client).pack(side=tk.LEFT)
        
        # Server statistics
        stats_frame = ttk.LabelFrame(right_frame, text="📊 Statistics", padding=10)
        stats_frame.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        
        self.stats_labels = {}
        stats_data = [
            ("messages_sent", "💬 Messages: 0"),
            ("files_sent", "📁 Files: 0"),
            ("uptime", "⏱️ Uptime: 00:00:00"),
            ("peak_clients", "📈 Peak Clients: 0")
        ]
        
        for i, (key, text) in enumerate(stats_data):
            label = ttk.Label(stats_frame, text=text, style="Info.TLabel")
            label.grid(row=i//2, column=i%2, sticky="w", padx=5, pady=2)
            self.stats_labels[key] = label
            
    def build_status_bar(self, parent):
        """Build the status bar"""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        
        # Status indicator
        self.status_label = ttk.Label(status_frame, text="⏹️ Server Stopped", 
                                     style="Status.TLabel", foreground="red")
        self.status_label.pack(side=tk.LEFT)
        
        # Server IP
        self.ip_label = ttk.Label(status_frame, text="", style="Info.TLabel")
        self.ip_label.pack(side=tk.LEFT, padx=(20, 0))
        
        # Current time
        self.time_label = ttk.Label(status_frame, text="", style="Info.TLabel")
        self.time_label.pack(side=tk.RIGHT)
        
        # Update time every second
        self.update_time()
        
    def update_time(self):
        """Update the current time display"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=f"🕐 {current_time}")
        self.root.after(1000, self.update_time)
        
    def get_local_ip(self):
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
            
    def start_server(self):
        """Start the chat server"""
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("❌ Error", "Please enter a valid port number.")
            return
            
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to all interfaces (0.0.0.0) so clients can connect from other machines
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)
            
            self.is_running = True
            self.start_time = datetime.now()
            
            # Update UI
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text="🟢 Server Running", foreground="green")
            
            # Show both local IP and 0.0.0.0 for clarity
            local_ip = self.get_local_ip()
            self.ip_label.config(text=f"📡 0.0.0.0:{port} (Local: {local_ip}:{port})")
            
            # Log server start
            self.log_message("🚀 Server started successfully", "success")
            self.log_message(f"📡 Listening on 0.0.0.0:{port}", "info")
            self.log_message(f"📡 Local IP: {local_ip}:{port}", "info")
            self.log_message("⏳ Waiting for client connections...", "info")
            
            # Start accept thread
            self.accept_thread = threading.Thread(target=self.accept_clients, daemon=True)
            self.accept_thread.start()
            
            # Start statistics update
            self.update_statistics()
            
        except Exception as e:
            messagebox.showerror("❌ Server Error", f"Failed to start server: {str(e)}")
            self.log_message(f"❌ Failed to start server: {str(e)}", "error")
            
    def stop_server(self):
        """Stop the chat server"""
        self.is_running = False
        
        # Close all client connections
        with self.client_lock:
            for client_socket in list(self.clients.keys()):
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()
            
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
            
        # Update UI
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="⏹️ Server Stopped", foreground="red")
        self.ip_label.config(text="")
        
        # Clear client list
        self.client_tree.delete(*self.client_tree.get_children())
        self.client_count_label.config(text="👥 Connected: 0")
        
        # Log server stop
        self.log_message("⏹️ Server stopped", "warning")
        
    def accept_clients(self):
        """Accept incoming client connections"""
        while self.is_running:
            try:
                if not self.server_socket:
                    break
                    
                self.server_socket.settimeout(1.0)  # Add timeout to prevent blocking
                client_socket, address = self.server_socket.accept()
                
                if not self.is_running:
                    client_socket.close()
                    break
                    
                self.log_message(f"🔗 Connection attempt from {address[0]}:{address[1]}", "info")
                
                # Start client handler thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
                
            except socket.timeout:
                continue  # This is expected, continue the loop
            except socket.error as e:
                if self.is_running:
                    self.message_queue.put(("log", f"❌ Socket error accepting client: {str(e)}", "error"))
                break
            except Exception as e:
                if self.is_running:
                    self.message_queue.put(("log", f"❌ Unexpected error: {str(e)}", "error"))
                break
                
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        username = None
        client_id = f"{address[0]}:{address[1]}"
        
        try:
            # Set timeout for receiving username
            client_socket.settimeout(30.0)
            
            # Receive username
            username_data = client_socket.recv(1024)
            if not username_data:
                self.message_queue.put(("log", f"❌ No username received from {address[0]}:{address[1]}", "error"))
                return
                
            username = username_data.decode('utf-8').strip()
            if not username:
                self.message_queue.put(("log", f"❌ Empty username from {address[0]}:{address[1]}", "error"))
                return
                
            self.message_queue.put(("log", f"📝 Received username: {username} from {address[0]}:{address[1]}", "info"))
            
            # Add client to dictionary
            with self.client_lock:
                self.clients[client_socket] = {
                    'username': username,
                    'address': address,
                    'connected_at': datetime.now(),
                    'messages_sent': 0,
                    'files_sent': 0
                }
                
            # Update UI
            self.message_queue.put(("client_connected", username, address))
            self.message_queue.put(("log", f"👋 {username} connected from {address[0]}:{address[1]}", "client"))
            
            # Send welcome message to client
            try:
                welcome_msg = f"Welcome to the server, {username}!"
                client_socket.sendall(welcome_msg.encode('utf-8'))
            except:
                pass
            
            # Set timeout for regular message handling
            client_socket.settimeout(5.0)
            
            # Handle client messages
            while self.is_running:
                try:
                    choice_data = client_socket.recv(1024)
                    if not choice_data:
                        self.message_queue.put(("log", f"❌ Client {username} disconnected unexpectedly", "warning"))
                        break
                        
                    choice = choice_data.decode('utf-8').strip()
                    self.message_queue.put(("log", f"📨 Received choice '{choice}' from {username}", "info"))
                    
                    if choice == "m":
                        self.handle_message(client_socket, username)
                    elif choice == "f":
                        self.handle_file(client_socket, username)
                    else:
                        self.message_queue.put(("log", f"⚠️ Invalid choice '{choice}' from {username}", "warning"))
                        
                except socket.timeout:
                    continue
                except socket.error as e:
                    if self.is_running:
                        self.message_queue.put(("log", f"❌ Socket error with {username}: {str(e)}", "error"))
                    break
                except Exception as e:
                    if self.is_running:
                        self.message_queue.put(("log", f"❌ Error handling {username}: {str(e)}", "error"))
                    break
                    
        except Exception as e:
            if self.is_running:
                self.message_queue.put(("log", f"❌ Error in client handler: {str(e)}", "error"))
        finally:
            # Clean up client
            try:
                client_socket.close()
            except:
                pass
                
            # Remove from clients dictionary
            with self.client_lock:
                if client_socket in self.clients:
                    del self.clients[client_socket]
                    
            # Update UI
            if username:
                self.message_queue.put(("client_disconnected", username, address))
                self.message_queue.put(("log", f"👋 {username} disconnected", "client"))
                
    def handle_message(self, client_socket, username):
        """Handle text message from client"""
        try:
            data = client_socket.recv(1024)
            if data:
                message = data.decode('utf-8')
                
                # Update statistics
                with self.client_lock:
                    if client_socket in self.clients:
                        self.clients[client_socket]['messages_sent'] += 1
                        
                # Log message
                self.message_queue.put(("log", f"💬 {username}: {message}", "message"))
                
                # Echo message back to client (for testing)
                try:
                    echo_msg = f"Echo: {message}"
                    client_socket.sendall(echo_msg.encode('utf-8'))
                except:
                    pass
                
        except Exception as e:
            self.message_queue.put(("log", f"❌ Error receiving message from {username}: {str(e)}", "error"))
            
    def handle_file(self, client_socket, username):
        """Handle file transfer from client"""
        try:
            ending_string = b'FILE_TRANSMISSION_COMPLETE'
            data = client_socket.recv(1024)
            
            if data.startswith(b"file:"):
                filename = data.decode('utf-8')[5:].strip()
                
                # Create received_files directory
                os.makedirs("received_files", exist_ok=True)
                file_path = os.path.join("received_files", f"{username}_{filename}")
                
                # Receive file data
                with open(file_path, "wb") as f:
                    while True:
                        data = client_socket.recv(1024)
                        if data.endswith(ending_string):
                            f.write(data[:-len(ending_string)])
                            break
                        f.write(data)
                        
                # Update statistics
                with self.client_lock:
                    if client_socket in self.clients:
                        self.clients[client_socket]['files_sent'] += 1
                        
                # Log file transfer
                file_size = os.path.getsize(file_path)
                self.message_queue.put(("log", f"📁 {username} sent file: {filename} ({file_size} bytes)", "file"))
                
                # Send confirmation to client
                try:
                    confirm_msg = f"File {filename} received successfully"
                    client_socket.sendall(confirm_msg.encode('utf-8'))
                except:
                    pass
                
            else:
                self.message_queue.put(("log", f"⚠️ Invalid file data from {username}", "warning"))
                
        except Exception as e:
            self.message_queue.put(("log", f"❌ Error receiving file from {username}: {str(e)}", "error"))
            
    def broadcast_message(self, sender_username, message, sender_socket=None):
        """Broadcast message to all connected clients"""
        broadcast_data = f"{sender_username}: {message}".encode('utf-8')
        
        with self.client_lock:
            for client_socket in list(self.clients.keys()):
                if client_socket != sender_socket:
                    try:
                        client_socket.sendall(broadcast_data)
                    except:
                        # Remove disconnected client
                        if client_socket in self.clients:
                            del self.clients[client_socket]
                            
    def process_messages(self):
        """Process messages from the queue for thread-safe UI updates"""
        try:
            while True:
                message = self.message_queue.get_nowait()
                
                if message[0] == "log":
                    self.log_message(message[1], message[2])
                elif message[0] == "client_connected":
                    self.update_client_list()
                elif message[0] == "client_disconnected":
                    self.update_client_list()
                    
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_messages)
            
    def log_message(self, message, level="info"):
        """Add a log message to the display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.log_display.config(state=tk.NORMAL)
        self.log_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.log_display.insert(tk.END, f"{message}\n", level)
        self.log_display.config(state=tk.DISABLED)
        self.log_display.see(tk.END)
        
    def update_client_list(self):
        """Update the client list display"""
        # Clear existing items
        self.client_tree.delete(*self.client_tree.get_children())
        
        # Add current clients
        with self.client_lock:
            for i, (socket, client_info) in enumerate(self.clients.items(), 1):
                self.client_tree.insert("", tk.END, iid=str(i), text=str(i),
                                       values=(client_info['username'], 
                                             client_info['address'][0],
                                             client_info['connected_at'].strftime("%H:%M:%S")))
                                             
            # Update client count
            client_count = len(self.clients)
            self.client_count_label.config(text=f"👥 Connected: {client_count}")
            
    def update_statistics(self):
        """Update server statistics"""
        if not self.is_running:
            return
            
        # Calculate uptime
        if hasattr(self, 'start_time'):
            uptime = datetime.now() - self.start_time
            uptime_str = str(uptime).split('.')[0]  # Remove microseconds
            self.stats_labels['uptime'].config(text=f"⏱️ Uptime: {uptime_str}")
            
        # Update other statistics
        with self.client_lock:
            total_messages = sum(client['messages_sent'] for client in self.clients.values())
            total_files = sum(client['files_sent'] for client in self.clients.values())
            current_clients = len(self.clients)
            
            self.stats_labels['messages_sent'].config(text=f"💬 Messages: {total_messages}")
            self.stats_labels['files_sent'].config(text=f"📁 Files: {total_files}")
            
            # Update peak clients
            if not hasattr(self, 'peak_clients'):
                self.peak_clients = 0
            if current_clients > self.peak_clients:
                self.peak_clients = current_clients
                
            self.stats_labels['peak_clients'].config(text=f"📈 Peak Clients: {self.peak_clients}")
            
        # Schedule next update
        self.root.after(1000, self.update_statistics)
        
    def refresh_clients(self):
        """Refresh the client list"""
        self.update_client_list()
        self.log_message("🔄 Client list refreshed", "info")
        
    def kick_client(self):
        """Kick selected client"""
        selected_item = self.client_tree.selection()
        if not selected_item:
            messagebox.showwarning("⚠️ Warning", "Please select a client to kick.")
            return
            
        # Get client info
        item = self.client_tree.item(selected_item[0])
        username = item['values'][0]
        
        # Confirm action
        if messagebox.askyesno("❓ Confirm", f"Are you sure you want to kick {username}?"):
            # Find and disconnect client
            with self.client_lock:
                for client_socket, client_info in list(self.clients.items()):
                    if client_info['username'] == username:
                        try:
                            client_socket.close()
                        except:
                            pass
                        if client_socket in self.clients:
                            del self.clients[client_socket]
                        break
                        
            self.log_message(f"⚠️ Kicked client: {username}", "warning")
            self.update_client_list()
            
    def clear_logs(self):
        """Clear the log display"""
        self.log_display.config(state=tk.NORMAL)
        self.log_display.delete(1.0, tk.END)
        self.log_display.config(state=tk.DISABLED)
        
    def on_closing(self):
        """Handle application closing"""
        if self.is_running:
            self.stop_server()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ProfessionalChatServer(root)
    root.mainloop()