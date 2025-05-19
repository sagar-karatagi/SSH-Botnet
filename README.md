# SSH Botnet Controller

## ⚠️ Educational Purpose Only ⚠️

This project is a Python-based SSH botnet controller created for **educational purposes only**. It demonstrates concepts related to network security, SSH automation, and basic botnet architecture. The application allows you to manage multiple SSH connections, execute commands remotely, and simulate (at very low intensity) DDoS attacks.

## Legal Disclaimer

**Using this software against targets without explicit permission is illegal and unethical.** The authors of this software do not endorse or encourage any malicious use of this tool. By using this software, you agree to use it responsibly and ethically.

The simulated DDoS functionality is heavily rate-limited and designed for educational demonstration only - it creates minimal traffic that would not impact real systems.

## Features

- Manage multiple SSH connections
- Connect to servers using username/password authentication
- Execute commands on single or multiple targets simultaneously
- Interactive shell mode for individual or all bots
- Password-protected encrypted storage of botnet configuration
- Educational DDoS attack simulation (heavily rate-limited)

## Requirements

- Python 3.6+
- pexpect
- scapy
- cryptography

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/ssh-botnet-controller.git
cd ssh-botnet-controller
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

Alternatively, you can install the dependencies automatically:

```bash
pip install .
```

### VS Code Setup

If you're using VS Code and see the warning "Import 'setuptools' could not be resolved", you can fix it by:

1. Install setuptools in your environment:

```bash
pip install setuptools
```

2. Make sure VS Code is using the correct Python interpreter:
   - Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
   - Type "Python: Select Interpreter" and select the appropriate Python environment
   - Restart VS Code

## Usage

Run the main program:

```bash
python main.py
```

### Main Menu Options

1. **List all bots** - View the status of all bots in your botnet
2. **Add a bot** - Add a new SSH connection to the botnet
3. **Remove a bot** - Remove a bot from the botnet
4. **Execute command on all bots** - Run a command on all connected bots
5. **Interactive shell** - Enter an interactive shell to control bots
6. **Perform DDoS attack simulation** - Run an educational DDoS simulation
7. **Save botnet** - Save the current botnet configuration (encrypted)
8. **Load botnet** - Load a saved botnet configuration
9. **Exit** - Close all connections and exit

### Security Features

- All bot passwords are encrypted with Fernet symmetric encryption
- A master password is required to encrypt/decrypt the botnet configuration
- Passwords are never stored in plaintext

## Code Structure

- `main.py` - Main program with menu-driven interface
- `bot.py` - Contains the Bot and Botnet classes for SSH connections

## Educational Notes

This project demonstrates several important security concepts:

- Password encryption and security
- SSH automation
- Command and control architecture
- Basic network attack vectors
- Authentication mechanics

## License

[MIT License](LICENSE)

## Contributing

Contributions for educational improvements are welcome. Please ensure that any contributions maintain the educational focus of this project and do not enhance its capability to perform harmful actions.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
